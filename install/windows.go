//go:build windows

package install

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/certkit-io/certkit-agent/config"
	"github.com/certkit-io/certkit-agent/utils"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	DefaultWindowsConfigPath  = `C:\ProgramData\CertKit\certkit-agent\config.json`
	defaultServiceDescription = "CertKit Agent service"
	windowsUninstallRegPath   = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\CertKit Agent`
	windowsEventLogSource     = "CertKit"
	windowsEventLogAppRegPath = `SYSTEM\CurrentControlSet\Services\EventLog\Application`
)

func InstallWindows(args []string, defaultServiceName string) {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	serviceName := fs.String("service-name", defaultServiceName, "windows service name")
	configPath := fs.String("config", DefaultWindowsConfigPath, "path to config.json")
	key := fs.String("key", "", "registration key used when creating a new config")
	fs.Parse(args)

	exe, err := os.Executable()
	if err != nil {
		log.Fatalf("failed to determine executable path: %v", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		log.Fatalf("failed to resolve executable symlinks: %v", err)
	}

	if _, err := os.Stat(exe); err != nil {
		log.Fatalf("binary path does not exist: %s (%v)", exe, err)
	}
	if !filepath.IsAbs(exe) {
		log.Fatalf("executable path must be absolute: %s", exe)
	}
	if !filepath.IsAbs(*configPath) {
		log.Fatalf("--config must be an absolute path: %s", *configPath)
	}

	if err := os.MkdirAll(filepath.Dir(*configPath), 0o755); err != nil {
		log.Fatalf("failed to create config dir: %v", err)
	}

	if _, err := os.Stat(*configPath); os.IsNotExist(err) {
		log.Printf("Config not found, creating %s", *configPath)
		if err := config.CreateInitialConfig(*configPath, *key, *serviceName); err != nil {
			log.Fatalf("failed to create config: %v", err)
		}
	} else {
		log.Printf("Config already exists at %s", *configPath)
	}

	if err := config.SetBootstrapServiceName(*configPath, *serviceName); err != nil {
		log.Fatalf("failed to persist service name in config: %v", err)
	}

	if err := ensureWindowsEventLogSource(); err != nil {
		log.Printf("Warning: failed to register Windows Event Log source %q: %v", windowsEventLogSource, err)
	}

	manager, err := mgr.Connect()
	if err != nil {
		log.Fatalf("failed to connect to service manager: %v", err)
	}
	defer manager.Disconnect()

	svcObj, err := manager.OpenService(*serviceName)
	if err != nil {
		svcObj, err = manager.CreateService(
			*serviceName,
			exe,
			mgr.Config{
				DisplayName:      *serviceName,
				StartType:        mgr.StartAutomatic,
				DelayedAutoStart: true,
				ServiceStartName: "LocalSystem",
				Description:      defaultServiceDescription,
			},
			"run",
			"--service",
			"--service-name",
			*serviceName,
			"--config",
			*configPath,
		)
		if err != nil {
			log.Fatalf("failed to create service %s: %v", *serviceName, err)
		}
		defer svcObj.Close()
	} else {
		defer svcObj.Close()
		binLine := fmt.Sprintf(`"%s" run --service --service-name "%s" --config "%s"`, exe, *serviceName, *configPath)
		current, err := svcObj.Config()
		if err != nil {
			log.Fatalf("failed to read service config %s: %v", *serviceName, err)
		}
		current.DisplayName = *serviceName
		current.StartType = mgr.StartAutomatic
		current.DelayedAutoStart = true
		current.ServiceStartName = "LocalSystem"
		current.BinaryPathName = binLine
		current.Description = defaultServiceDescription
		if err := svcObj.UpdateConfig(current); err != nil {
			log.Fatalf("failed to update service %s: %v", *serviceName, err)
		}
	}

	if err := configureRecovery(svcObj); err != nil {
		log.Fatalf("failed to configure service recovery: %v", err)
	}

	status, err := svcObj.Query()
	if err != nil {
		log.Fatalf("failed to query service %s: %v", *serviceName, err)
	}
	if status.State != svc.Running {
		if err := svcObj.Start(); err != nil {
			log.Fatalf("failed to start service %s: %v", *serviceName, err)
		}
	}

	machineId, _ := utils.GetStableMachineID()
	log.Printf("Installed and started %s on machine: %s", *serviceName, machineId)
	log.Printf("   Get-Service %s", *serviceName)
	log.Printf("Service runs as LocalSystem for LocalMachine cert store access.")
}

func UninstallWindows(args []string, defaultServiceName string) {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	serviceName := fs.String("service-name", defaultServiceName, "windows service name")
	configPath := fs.String("config", DefaultWindowsConfigPath, "path to config.json")
	fs.Parse(args)

	manager, err := mgr.Connect()
	if err != nil {
		log.Fatalf("failed to connect to service manager: %v", err)
	}
	defer manager.Disconnect()

	svcObj, err := manager.OpenService(*serviceName)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			log.Printf("Service %s does not exist; nothing to remove", *serviceName)
		} else {
			log.Fatalf("failed to open service %s: %v", *serviceName, err)
		}
	} else {
		defer svcObj.Close()
		if err := stopWindowsService(svcObj, *serviceName); err != nil {
			log.Fatalf("failed to stop service %s: %v", *serviceName, err)
		}
		if err := svcObj.Delete(); err != nil {
			log.Fatalf("failed to delete service %s: %v", *serviceName, err)
		}
		log.Printf("Deleted service %s", *serviceName)
	}

	if err := removeWindowsUninstallRegistryEntry(); err != nil {
		log.Printf("Warning: failed to remove Add/Remove Programs entry: %v", err)
	}
	if err := removeWindowsEventLogSource(); err != nil {
		log.Printf("Warning: failed to remove Windows Event Log source %q: %v", windowsEventLogSource, err)
	}

	unregisterAgent(*configPath)

	if err := os.Remove(*configPath); err != nil && !os.IsNotExist(err) {
		log.Fatalf("failed to remove config file %s: %v", *configPath, err)
	}
	log.Printf("Removed config file %s", *configPath)

	if err := removeAgentProgramData(*configPath); err != nil {
		log.Fatalf("failed to remove agent data from ProgramData: %v", err)
	}

	log.Printf("Uninstall completed for service %s", *serviceName)
}

// removeAgentProgramData deletes the agent's own data from %ProgramData%\CertKit:
// the directory holding its config and log, and its persisted machine identity.
// Other CertKit products share that folder (certkit-keystore keeps its stored
// certificates there), so the CertKit folder itself is only removed once
// nothing else is left in it.
func removeAgentProgramData(configPath string) error {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		return nil
	}
	certkitDir := filepath.Join(programData, "CertKit")

	// Only delete the config directory when it sits directly inside the CertKit
	// folder (certkit-agent by default); a custom --config elsewhere may share
	// its directory with unrelated files. Clean first: older script installs
	// baked doubled backslashes into the path, and filepath.Dir keeps them.
	configDir := filepath.Dir(filepath.Clean(configPath))
	if strings.EqualFold(filepath.Dir(configDir), certkitDir) {
		if err := os.RemoveAll(configDir); err != nil {
			return fmt.Errorf("remove agent data directory %s: %w", configDir, err)
		}
		log.Printf("Removed agent data directory %s", configDir)
	}

	// utils.GetStableMachineID only writes this file when MachineGuid is unreadable.
	agentIDPath := filepath.Join(certkitDir, "agent-id")
	if err := os.Remove(agentIDPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove agent identity file %s: %w", agentIDPath, err)
	}

	entries, err := os.ReadDir(certkitDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read directory %s: %w", certkitDir, err)
	}
	if len(entries) > 0 {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		log.Printf("Leaving %s in place; it still contains: %s", certkitDir, strings.Join(names, ", "))
		return nil
	}
	// os.Remove (unlike RemoveAll) refuses a directory that is no longer empty.
	if err := os.Remove(certkitDir); err != nil {
		return fmt.Errorf("remove empty directory %s: %w", certkitDir, err)
	}
	log.Printf("Removed empty directory %s", certkitDir)
	return nil
}

func configureRecovery(s *mgr.Service) error {
	return s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
	}, 86400)
}

func stopWindowsService(s *mgr.Service, serviceName string) error {
	status, err := s.Query()
	if err != nil {
		return fmt.Errorf("query: %w", err)
	}
	if status.State == svc.Stopped {
		return nil
	}

	if _, err := s.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
		return fmt.Errorf("stop: %w", err)
	}

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		status, err = s.Query()
		if err != nil {
			return fmt.Errorf("query after stop: %w", err)
		}
		if status.State == svc.Stopped {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}

	return fmt.Errorf("service %s did not stop in time", serviceName)
}

func removeWindowsUninstallRegistryEntry() error {
	err := registry.DeleteKey(registry.LOCAL_MACHINE, windowsUninstallRegPath)
	if err != nil && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) && !errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return err
	}
	return nil
}

func ensureWindowsEventLogSource() error {
	appkey, err := registry.OpenKey(registry.LOCAL_MACHINE, windowsEventLogAppRegPath, registry.CREATE_SUB_KEY)
	if err != nil {
		return err
	}
	defer appkey.Close()

	sk, _, err := registry.CreateKey(appkey, windowsEventLogSource, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return err
	}
	defer sk.Close()

	messageFile := selectWindowsEventMessageFile()
	if err := sk.SetDWordValue("CustomSource", 1); err != nil {
		return err
	}
	if err := sk.SetExpandStringValue("EventMessageFile", messageFile); err != nil {
		return err
	}
	if err := sk.SetDWordValue("TypesSupported", eventlog.Error|eventlog.Warning|eventlog.Info); err != nil {
		return err
	}

	if el, err := eventlog.Open(windowsEventLogSource); err == nil {
		_ = el.Close()
	}

	return nil
}

func removeWindowsEventLogSource() error {
	err := eventlog.Remove(windowsEventLogSource)
	if err != nil && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) && !errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return err
	}
	return nil
}

func selectWindowsEventMessageFile() string {
	candidates := []string{
		`%SystemRoot%\System32\EventCreate.exe`,
		`%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\EventLogMessages.dll`,
		`%SystemRoot%\Microsoft.NET\Framework\v4.0.30319\EventLogMessages.dll`,
	}

	for _, candidate := range candidates {
		expanded := os.ExpandEnv(candidate)
		if _, err := os.Stat(expanded); err == nil {
			return candidate
		}
	}

	return candidates[len(candidates)-1]
}
