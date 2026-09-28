//go:build windows

package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	agentinstall "github.com/certkit-io/certkit-agent/install"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const defaultConfigPath = agentinstall.DefaultWindowsConfigPath

func usageAndExit() {
	fmt.Fprintf(os.Stderr, `Certkit Agent %s

Usage:
  certkit-agent install    [--service-name NAME] [--config PATH] [--key REGISTRATION_KEY]
  certkit-agent uninstall  [--service-name NAME] [--config PATH]
  certkit-agent bootstrap-config [--service-name NAME] [--config PATH] [--key REGISTRATION_KEY]   (used by the MSI installer)
  certkit-agent msi-cleanup      [--config PATH]                                                  (used by the MSI installer)
  certkit-agent run        [--config PATH] [--once] [--key REGISTRATION_KEY]
  certkit-agent register   REGISTRATION_KEY [--config PATH]
  certkit-agent validate   [--config PATH]
  certkit-agent lock       [--config PATH]
  certkit-agent unlock     [--config PATH]
  certkit-agent version
`, version)
	os.Exit(2)
}

func installCmd(args []string) {
	mustBeAdmin()
	agentinstall.InstallWindows(args, defaultServiceName)
}

func uninstallCmd(args []string) {
	mustBeAdmin()
	agentinstall.UninstallWindows(args, defaultServiceName)
}

func bootstrapConfigCmd(args []string) {
	mustBeAdmin()
	agentinstall.BootstrapConfigWindows(args, defaultServiceName)
}

func msiCleanupCmd(args []string) {
	mustBeAdmin()
	agentinstall.MsiCleanupWindows(args)
}

func runCmd(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	// Hidden internal option used by SCM service invocations.
	serviceName := fs.String("service-name", defaultServiceName, "windows service name")
	configPath := fs.String("config", defaultConfigPath, "path to config.json")
	forceService := fs.Bool("service", false, "force service mode (used by SCM)")
	runOnce := fs.Bool("once", false, "run register/poll/sync once and exit")
	key := fs.String("key", "", "registration key used when creating a new config")
	fs.Parse(args)

	isService, err := svc.IsWindowsService()
	if *runOnce {
		if *forceService || (err == nil && isService) {
			log.Fatal("--once cannot be used in service mode")
		}
		mustBeAdmin()
		setLogOutputWithEventLog(os.Stdout)
		runAgent(runOptions{
			configPath:  *configPath,
			stopCh:      nil,
			runOnce:     true,
			key:         *key,
			serviceName: *serviceName,
		})
		return
	}

	if *forceService || (err == nil && isService) {
		log.Printf("Running as windows service...")
		runWindowsService(*serviceName, *configPath)
		return
	}

	mustBeAdmin()
	setLogOutputWithEventLog(os.Stdout)

	stopCh := make(chan struct{})
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		sig := <-sigCh
		log.Printf("received signal %s, shutting down", sig)
		close(stopCh)
	}()

	runAgent(runOptions{
		configPath:  *configPath,
		stopCh:      stopCh,
		runOnce:     false,
		key:         *key,
		serviceName: *serviceName,
	})
}

func registerCmd(args []string) {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "path to config.json")
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		fmt.Fprintln(os.Stderr, "Usage: certkit-agent register REGISTRATION_KEY [--config PATH]")
		os.Exit(1)
	}
	key := strings.TrimSpace(args[0])
	if key == "" {
		fmt.Fprintln(os.Stderr, "Usage: certkit-agent register REGISTRATION_KEY [--config PATH]")
		os.Exit(1)
	}
	fs.Parse(args[1:])
	if len(fs.Args()) > 0 {
		fmt.Fprintln(os.Stderr, "Usage: certkit-agent register REGISTRATION_KEY [--config PATH]")
		os.Exit(1)
	}

	mustBeAdmin()

	if err := doRegister(*configPath, key); err != nil {
		log.Fatal(err)
	}
}

func validateCmd(args []string) {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "path to config.json")
	fs.Parse(args)

	if err := doValidate(*configPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func lockCmd(args []string) {
	fs := flag.NewFlagSet("lock", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "path to config.json")
	fs.Parse(args)

	mustBeAdmin()

	if err := doLock(*configPath); err != nil {
		log.Fatal(err)
	}
}

func unlockCmd(args []string) {
	fs := flag.NewFlagSet("unlock", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "path to config.json")
	fs.Parse(args)

	mustBeAdmin()

	if err := doUnlock(*configPath); err != nil {
		log.Fatal(err)
	}
}

func runWindowsService(serviceName, configPath string) {
	if err := svc.Run(serviceName, &windowsService{configPath: configPath, serviceName: serviceName}); err != nil {
		log.Fatalf("service failed: %v", err)
	}
}

type windowsService struct {
	configPath  string
	serviceName string
}

func (s *windowsService) Execute(_ []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown

	changes <- svc.Status{State: svc.StartPending}

	initServiceLogging(s.configPath)

	stopCh := make(chan struct{})
	done := make(chan struct{})
	go func() {
		runAgent(runOptions{
			configPath:  s.configPath,
			stopCh:      stopCh,
			runOnce:     false,
			key:         "",
			serviceName: s.serviceName,
		})
		close(done)
	}()

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	if err := ensureDelayedAutoStart(s.serviceName); err != nil {
		log.Printf("Warning: failed to set delayed auto-start on service %s: %v", s.serviceName, err)
	}

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

// ensureDelayedAutoStart switches an Automatic service to Automatic (Delayed
// Start). Installs made before delayed start was the default never re-run the
// installer (self-update only swaps the exe), so the running service fixes
// itself. Manual/Disabled services are left alone.
func ensureDelayedAutoStart(serviceName string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("open service: %w", err)
	}
	defer s.Close()

	cfg, err := s.Config()
	if err != nil {
		return fmt.Errorf("read service config: %w", err)
	}
	if cfg.StartType != mgr.StartAutomatic || cfg.DelayedAutoStart {
		return nil
	}

	// Change only the delayed-start flag; UpdateConfig would rewrite the
	// whole service config.
	info := windows.SERVICE_DELAYED_AUTO_START_INFO{IsDelayedAutoStartUp: 1}
	if err := windows.ChangeServiceConfig2(s.Handle, windows.SERVICE_CONFIG_DELAYED_AUTO_START_INFO, (*byte)(unsafe.Pointer(&info))); err != nil {
		return fmt.Errorf("change service config: %w", err)
	}
	log.Printf("Set service %s to Automatic (Delayed Start)", serviceName)
	return nil
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
	maxLogSize = 5 * 1024 * 1024
	keepLines  = 10000
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
	setLogOutputWithEventLog(f)
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
		setLogOutputWithEventLog(newFile)
		old := current
		current = newFile
		old.Close()
	}
}
