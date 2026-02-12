//go:build !windows

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	agentinstall "github.com/certkit-io/certkit-agent/install"
)

const (
	defaultUnitPath   = agentinstall.DefaultLinuxUnitPath
	defaultConfigPath = agentinstall.DefaultLinuxConfigPath
)

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
	agentinstall.InstallLinux(args, defaultServiceName)
}

func uninstallCmd(args []string) {
	agentinstall.UninstallLinux(args, defaultServiceName)
}

func runCmd(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "path to config.json")
	runOnce := fs.Bool("run-once", false, "run register/poll/sync once and exit")
	key := fs.String("key", "", "registration key used when creating a new config")
	fs.Parse(args)

	if *runOnce {
		runAgent(runOptions{
			configPath: *configPath,
			stopCh:     nil,
			runOnce:    true,
			key:        *key,
		})
		return
	}

	stopCh := make(chan struct{})
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
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
