//go:build windows

package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/certkit-io/certkit-agent/config"
	"github.com/certkit-io/certkit-agent/utils"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const defaultConfigPath = `C:\ProgramData\CertKit\certkit-agent\config.json`
const defaultServiceDescription = "CertKit Agent service"
const windowsUninstallRegPath = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\CertKit Agent`

func usageAndExit() {
	fmt.Fprintf(os.Stderr, `Certkit Agent %s

Usage:
  certkit-agent install [--service-name NAME] [--bin-path PATH] [--config PATH]
  certkit-agent uninstall [--service-name NAME] [--config PATH]
  certkit-agent run     [--service-name NAME] [--config PATH] [--service]

Examples (elevated PowerShell):
  .\certkit-agent.exe install
  .\certkit-agent.exe uninstall
  Get-Service certkit-agent
  .\certkit-agent.exe run --config "%s"
`, version, defaultConfigPath)
	os.Exit(2)
}

func installCmd(args []string) {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	serviceName := fs.String("service-name", defaultServiceName, "windows service name")
	binPath := fs.String("bin-path", "", "path to certkit-agent binary (default: current executable)")
	configPath := fs.String("config", defaultConfigPath, "path to config.json")
	fs.Parse(args)

	mustBeAdmin()

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

func runCmd(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	serviceName := fs.String("service-name", defaultServiceName, "windows service name")
	configPath := fs.String("config", defaultConfigPath, "path to config.json")
	forceService := fs.Bool("service", false, "force service mode (used by SCM)")
	fs.Parse(args)

	isService, err := svc.IsWindowsService()
	if *forceService || (err == nil && isService) {
		log.Printf("Running as windows service...")
		runWindowsService(*serviceName, *configPath)
		return
	}

	mustBeAdmin()

	stopCh := make(chan struct{})
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		sig := <-sigCh
		log.Printf("received signal %s, shutting down", sig)
		close(stopCh)
	}()

	runAgent(*configPath, stopCh)
}

func uninstallCmd(args []string) {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	serviceName := fs.String("service-name", defaultServiceName, "windows service name")
	configPath := fs.String("config", defaultConfigPath, "path to config.json")
	fs.Parse(args)

	mustBeAdmin()

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

func runWindowsService(serviceName, configPath string) {
	if err := svc.Run(serviceName, &windowsService{configPath: configPath}); err != nil {
		log.Fatalf("service failed: %v", err)
	}
}

type windowsService struct {
	configPath string
}

func (s *windowsService) Execute(_ []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown

	changes <- svc.Status{State: svc.StartPending}

	initServiceLogging(s.configPath)

	stopCh := make(chan struct{})
	done := make(chan struct{})
	go func() {
		runAgent(s.configPath, stopCh)
		close(done)
	}()

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			changes <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			close(stopCh)
			<-done
			changes <- svc.Status{State: svc.Stopped}
			return false, 0
		default:
		}
	}

	changes <- svc.Status{State: svc.StopPending}
	close(stopCh)
	<-done
	changes <- svc.Status{State: svc.Stopped}
	return false, 0
}

func mustBeAdmin() {
	ok, err := isElevatedAdmin()
	if err != nil {
		log.Fatalf("failed to check administrator elevation: %v", err)
	}
	if !ok {
		log.Fatal("this command must be run from an elevated Administrator prompt")
	}
}

func isElevatedAdmin() (bool, error) {
	token := windows.Token(0)
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return false, err
	}
	defer token.Close()

	if !token.IsElevated() {
		return false, nil
	}

	return true, nil
}

const (
	maxLogSize = 5 * 1024 * 1024 // trigger rotation at 5 MB
	keepLines  = 10000           // keep last 10k lines after rotation
)

func initServiceLogging(configPath string) {
	logFile := filepath.Join(filepath.Dir(configPath), "certkit-agent.log")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		return
	}
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	log.SetOutput(f)
	go logTruncator(logFile, f)
}

func logTruncator(logFile string, current *os.File) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		info, err := current.Stat()
		if err != nil || info.Size() < maxLogSize {
			continue
		}
		data, err := os.ReadFile(logFile)
		if err != nil {
			continue
		}
		lines := bytes.Split(data, []byte("\n"))
		if len(lines) <= keepLines {
			continue
		}
		kept := bytes.Join(lines[len(lines)-keepLines:], []byte("\n"))

		if err := os.WriteFile(logFile, kept, 0o644); err != nil {
			continue
		}
		newFile, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			continue
		}
		log.SetOutput(newFile)
		old := current
		current = newFile
		old.Close()
	}
}

func configureRecovery(s *mgr.Service) error {
	// Restart after 5s on first/second/subsequent failures; reset failure count after 1 day.
	return s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
	}, 86400) // reset failure count after 1 day
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
