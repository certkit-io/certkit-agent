//go:build !windows

package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/certkit-io/certkit-agent/config"
	"github.com/certkit-io/certkit-agent/utils"
)

const (
	defaultUnitPath   = "/etc/systemd/system"
	defaultConfigPath = "/etc/certkit-agent/config.json"
)

func usageAndExit() {
	fmt.Fprintf(os.Stderr, `Usage:
  certkit-agent install [--service-name NAME] [--unit-dir DIR] [--bin-path PATH] [--config PATH]
  certkit-agent run     [--config PATH]

Examples:
  sudo ./certkit-agent install
  sudo systemctl status certkit-agent
  ./certkit-agent run --config /etc/certkit-agent/config.json
`)
	os.Exit(2)
}

func installCmd(args []string) {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	serviceName := fs.String("service-name", defaultServiceName, "systemd service name")
	unitDir := fs.String("unit-dir", defaultUnitPath, "systemd unit directory")
	binPath := fs.String("bin-path", "", "path to certkit-agent binary (default: current executable)")
	configPath := fs.String("config", defaultConfigPath, "path to config.json")
	fs.Parse(args)

	mustBeRoot()

	// Determine binary path (the installed binary path you want systemd to execute).
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

	// Basic sanity checks.
	if _, err := os.Stat(exe); err != nil {
		log.Fatalf("binary path does not exist: %s (%v)", exe, err)
	}
	if !strings.HasPrefix(*unitDir, "/") {
		log.Fatalf("--unit-dir must be an absolute path: %s", *unitDir)
	}
	if !strings.HasPrefix(*configPath, "/") {
		log.Fatalf("--config must be an absolute path: %s", *configPath)
	}

	// Ensure config directory exists (config file contents are handled by your installer script).
	if err := os.MkdirAll(filepath.Dir(*configPath), 0o755); err != nil {
		log.Fatalf("failed to create config dir: %v", err)
	}

	// Ensure config exists or create it
	if _, err := os.Stat(*configPath); os.IsNotExist(err) {
		log.Printf("Config not found, creating %s", *configPath)
		if err := config.CreateInitialConfig(*configPath); err != nil {
			log.Fatalf("failed to create config: %v", err)
		}
	} else {
		log.Printf("Config already exists at %s", *configPath)
	}

	if _, err := exec.LookPath("systemctl"); err != nil {
		log.Printf("systemd not detected; skipping unit install. Run: %s run --config %s", exe, *configPath)
		return
	}

	unitPath := filepath.Join(*unitDir, *serviceName+".service")
	unitContent := renderSystemdUnit(exe, *configPath)

	// Write unit file atomically.
	if err := utils.WriteFileAtomic(unitPath, []byte(unitContent), 0o644); err != nil {
		log.Fatalf("failed to write unit file %s: %v", unitPath, err)
	}

	// systemd: daemon-reload, enable, start
	if err := runCmdLogged("systemctl", "daemon-reload"); err != nil {
		log.Fatalf("systemctl daemon-reload failed: %v", err)
	}
	if err := runCmdLogged("systemctl", "enable", "--now", *serviceName+".service"); err != nil {
		log.Fatalf("systemctl enable --now failed: %v", err)
	}

	machineId, _ := utils.GetStableMachineID()
	log.Printf("✅ Installed and started %s (unit: %s) on machine: %s", *serviceName, unitPath, machineId)
	log.Printf("   systemctl status %s.service", *serviceName)
}

func runCmd(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "path to config.json")
	fs.Parse(args)

	stopCh := make(chan struct{})
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("received signal %s, shutting down", sig)
		close(stopCh)
	}()

	runAgent(*configPath, stopCh)
}

// --- helpers ---

func mustBeRoot() {
	if os.Geteuid() != 0 {
		log.Fatal("this command must be run as root (try: sudo ...)")
	}
}

func renderSystemdUnit(exePath, configPath string) string {
	// Root-running service, with moderate hardening.
	// You can tighten further once you know all file paths the agent needs to write.
	return fmt.Sprintf(`[Unit]
Description=CertKit Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s run --config %s
Restart=always
RestartSec=5

# Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectControlGroups=true
ProtectKernelTunables=true
ProtectKernelModules=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictSUIDSGID=true

StateDirectory=certkit-agent
LogsDirectory=certkit-agent

[Install]
WantedBy=multi-user.target
`, shellEscape(exePath), shellEscape(configPath))
}

func shellEscape(s string) string {
	// systemd unit files treat ExecStart as a command line; spaces matter.
	// Easiest safe approach: wrap in quotes and escape embedded quotes/backslashes.
	// This is conservative and works well for typical paths.
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
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
		// Return a cleaner error with captured output.
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(out.String()))
	}
	return nil
}

// If you want to give a nicer error when systemctl isn't present.
func isCmdNotFound(err error) bool {
	var ee *exec.Error
	if errors.As(err, &ee) {
		return true
	}
	return false
}
