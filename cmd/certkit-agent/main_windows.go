//go:build windows

package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"

	"github.com/certkit-io/certkit-agent/config"
	"github.com/certkit-io/certkit-agent/utils"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const defaultConfigPath = `C:\ProgramData\CertKit\certkit-agent\config.json`
const defaultServiceDescription = "CertKit Agent service"

func usageAndExit() {
	fmt.Fprintf(os.Stderr, `Usage:
  certkit-agent install [--service-name NAME] [--bin-path PATH] [--config PATH]
  certkit-agent run     [--service-name NAME] [--config PATH]

Examples (elevated PowerShell):
  .\certkit-agent.exe install
  Get-Service certkit-agent
  .\certkit-agent.exe run --config "%s"
`, defaultConfigPath)
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
			"--config",
			*configPath,
		)
		if err != nil {
			log.Fatalf("failed to create service %s: %v", *serviceName, err)
		}
		defer svcObj.Close()
	} else {
		defer svcObj.Close()
		binLine := fmt.Sprintf(`"%s" run --config "%s"`, exe, *configPath)
		if err := svcObj.UpdateConfig(mgr.Config{
			DisplayName:      *serviceName,
			StartType:        mgr.StartAutomatic,
			ServiceStartName: "LocalSystem",
			BinaryPathName:   binLine,
			Description:      defaultServiceDescription,
		}); err != nil {
			log.Fatalf("failed to update service %s: %v", *serviceName, err)
		}
	}

	if err := configureRecovery(*serviceName); err != nil {
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
	log.Printf("✅ Installed and started %s on machine: %s", *serviceName, machineId)
	log.Printf("   Get-Service %s", *serviceName)
	log.Printf("Service runs as LocalSystem for LocalMachine cert store access.")
}

func runCmd(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	serviceName := fs.String("service-name", defaultServiceName, "windows service name")
	configPath := fs.String("config", defaultConfigPath, "path to config.json")
	fs.Parse(args)

	isService, err := svc.IsWindowsService()
	if err == nil && isService {
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

	adminSid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false, err
	}
	isMember, err := token.IsMember(adminSid)
	if err != nil {
		return false, err
	}
	return isMember, nil
}

func configureRecovery(serviceName string) error {
	// Restart after 5s on first/second/subsequent failures; reset failure count after 1 day.
	return runCmdLogged("sc.exe", "failure", serviceName, "reset=86400", "actions=restart/5000/restart/5000/restart/5000")
}

func runCmdLogged(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if out.Len() > 0 {
		log.Printf("%s %s:\n%s", name, strings.Join(args, " "), strings.TrimSpace(out.String()))
	}
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(out.String()))
	}
	return nil
}
