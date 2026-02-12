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

	agentinstall "github.com/certkit-io/certkit-agent/install"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

const defaultConfigPath = agentinstall.DefaultWindowsConfigPath

func usageAndExit() {
	fmt.Fprintf(os.Stderr, `Certkit Agent %s

Usage:
  certkit-agent install    [--service-name NAME] [--config PATH] [--key REGISTRATION_KEY]
  certkit-agent uninstall  [--service-name NAME] [--config PATH]
  certkit-agent run        [--config PATH] [--run-once] [--key REGISTRATION_KEY]
  certkit-agent register   --key REGISTRATION_KEY [--config PATH]
  certkit-agent validate   [--config PATH]
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

func runCmd(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	// Hidden internal option used by SCM service invocations.
	serviceName := fs.String("service-name", defaultServiceName, "windows service name")
	configPath := fs.String("config", defaultConfigPath, "path to config.json")
	forceService := fs.Bool("service", false, "force service mode (used by SCM)")
	runOnce := fs.Bool("run-once", false, "run register/poll/sync once and exit")
	key := fs.String("key", "", "registration key used when creating a new config")
	fs.Parse(args)

	isService, err := svc.IsWindowsService()
	if *runOnce {
		if *forceService || (err == nil && isService) {
			log.Fatal("--run-once cannot be used in service mode")
		}
		mustBeAdmin()
		runAgent(runOptions{
			configPath: *configPath,
			stopCh:     nil,
			runOnce:    true,
			key:        *key,
		})
		return
	}

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

	runAgent(runOptions{
		configPath: *configPath,
		stopCh:     stopCh,
		runOnce:    false,
		key:        *key,
	})
}

func registerCmd(args []string) {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "path to config.json")
	key := fs.String("key", "", "registration key")
	fs.Parse(args)

	mustBeAdmin()

	if strings.TrimSpace(*key) == "" {
		log.Fatal("--key is required")
	}

	if err := doRegister(*configPath, *key); err != nil {
		log.Fatal(err)
	}
}

func validateCmd(args []string) {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "path to config.json")
	fs.Parse(args)

	if err := doValidate(*configPath); err != nil {
		log.Fatal(err)
	}
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
		runAgent(runOptions{
			configPath: s.configPath,
			stopCh:     stopCh,
			runOnce:    false,
			key:        "",
		})
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
