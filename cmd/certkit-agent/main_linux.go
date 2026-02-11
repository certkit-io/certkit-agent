//go:build !windows

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
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
  certkit-agent install [--service-name NAME] [--unit-dir DIR] [--bin-path PATH] [--config PATH]
  certkit-agent uninstall [--service-name NAME] [--unit-dir DIR] [--config PATH]
  certkit-agent run     [--config PATH] [--run-once]

Examples:
  sudo ./certkit-agent install
  sudo ./certkit-agent uninstall
  sudo systemctl status certkit-agent
  ./certkit-agent run --config /etc/certkit-agent/config.json
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
	fs.Parse(args)

	if *runOnce {
		runAgent(*configPath, nil, true)
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

	runAgent(*configPath, stopCh, false)
}
