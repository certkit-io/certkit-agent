//go:build windows

package install

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/certkit-io/certkit-agent/config"
	"github.com/certkit-io/certkit-agent/utils"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	DefaultWindowsConfigPath  = `C:\ProgramData\CertKit\certkit-agent\config.json`
	defaultServiceDescription = "CertKit Agent service"
	windowsUninstallRegPath   = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\CertKit Agent`
)

func InstallWindows(args []string, defaultServiceName string) {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	serviceName := fs.String("service-name", defaultServiceName, "windows service name")
	binPath := fs.String("bin-path", "", "path to certkit-agent binary (default: current executable)")
	configPath := fs.String("config", DefaultWindowsConfigPath, "path to config.json")
	fs.Parse(args)

	exe := *binPath
	if exe == "" {
		var err error
		exe, err = os.Executable()
		if err != nil {
			log.Fatalf("failed to determine executable path: %v", err)
		}
		exe, err = filepath.EvalSymlinks(exe)
		if err != nil {
			log.Fatalf("failed to resolve executable symlinks: %v", err)
		}
	}

	if _, err := os.Stat(exe); err != nil {
		log.Fatalf("binary path does not exist: %s (%v)", exe, err)
	}
	if !filepath.IsAbs(exe) {
		log.Fatalf("--bin-path must be an absolute path: %s", exe)
	}
	if !filepath.IsAbs(*configPath) {
		log.Fatalf("--config must be an absolute path: %s", *configPath)
	}

	if err := os.MkdirAll(filepath.Dir(*configPath), 0o755); err != nil {
		log.Fatalf("failed to create config dir: %v", err)
	}

	if _, err := os.Stat(*configPath); os.IsNotExist(err) {
		log.Printf("Config not found, creating %s", *configPath)
		if err := config.CreateInitialConfig(*configPath); err != nil {
			log.Fatalf("failed to create config: %v", err)
		}
	} else {
		log.Printf("Config already exists at %s", *configPath)
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
				ServiceStartName: "LocalSystem",
				Description:      defaultServiceDescription,
			},
			"run",
			"--service",
			"--config",
			*configPath,
		)
		if err != nil {
			log.Fatalf("failed to create service %s: %v", *serviceName, err)
		}
		defer svcObj.Close()
	} else {
		defer svcObj.Close()
		binLine := fmt.Sprintf(`"%s" run --service --config "%s"`, exe, *configPath)
		current, err := svcObj.Config()
		if err != nil {
			log.Fatalf("failed to read service config %s: %v", *serviceName, err)
		}
		current.DisplayName = *serviceName
		current.StartType = mgr.StartAutomatic
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

	if err := os.Remove(*configPath); err != nil && !os.IsNotExist(err) {
		log.Fatalf("failed to remove config file %s: %v", *configPath, err)
	}
	log.Printf("Removed config file %s", *configPath)

	programData := os.Getenv("ProgramData")
	if programData != "" {
		programDataCertKit := filepath.Join(programData, "CertKit")
		if err := os.RemoveAll(programDataCertKit); err != nil {
			log.Fatalf("failed to remove ProgramData directory %s: %v", programDataCertKit, err)
		}
		log.Printf("Removed ProgramData directory %s", programDataCertKit)
	}

	log.Printf("Uninstall completed for service %s", *serviceName)
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
