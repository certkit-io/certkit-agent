//go:build !windows

package install

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/certkit-io/certkit-agent/config"
	"github.com/certkit-io/certkit-agent/utils"
)

const (
	DefaultLinuxUnitPath   = "/etc/systemd/system"
	DefaultLinuxConfigPath = "/etc/certkit-agent/config.json"
)

func InstallLinux(args []string, defaultServiceName string) {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	serviceName := fs.String("service-name", defaultServiceName, "systemd service name")
	configPath := fs.String("config", DefaultLinuxConfigPath, "path to config.json")
	key := fs.String("key", "", "registration key used when creating a new config")
	fs.Parse(args)

	mustBeRoot()

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
	if !strings.HasPrefix(*configPath, "/") {
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

	if _, err := exec.LookPath("systemctl"); err != nil {
		log.Printf("systemd not detected; skipping unit install. Run: %s run --config %s", exe, *configPath)
		return
	}

	unitPath := filepath.Join(DefaultLinuxUnitPath, *serviceName+".service")
	unitContent := renderSystemdUnit(exe, *configPath)

	if err := utils.WriteFileAtomic(unitPath, []byte(unitContent), 0o644); err != nil {
		log.Fatalf("failed to write unit file %s: %v", unitPath, err)
	}

	if err := runCmdLogged("systemctl", "daemon-reload"); err != nil {
		log.Fatalf("systemctl daemon-reload failed: %v", err)
	}
	if err := runCmdLogged("systemctl", "enable", "--now", *serviceName+".service"); err != nil {
		log.Fatalf("systemctl enable --now failed: %v", err)
	}

	machineId, _ := utils.GetStableMachineID()
	log.Printf("Installed and started %s (unit: %s) on machine: %s", *serviceName, unitPath, machineId)
	log.Printf("   systemctl status %s.service", *serviceName)
}

func UninstallLinux(args []string, defaultServiceName string) {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	serviceName := fs.String("service-name", defaultServiceName, "systemd service name")
	configPath := fs.String("config", DefaultLinuxConfigPath, "path to config.json")
	fs.Parse(args)
	configPathExplicit := isFlagExplicitlySet(fs, "config")

	mustBeRoot()

	if !strings.HasPrefix(*configPath, "/") {
		log.Fatalf("--config must be an absolute path: %s", *configPath)
	}

	unitName := *serviceName + ".service"
	unitPath := filepath.Join(DefaultLinuxUnitPath, unitName)
	unitExists := false
	binaryPath := ""
	if _, err := os.Stat(unitPath); err == nil {
		unitExists = true
		path, err := binaryPathFromSystemdUnit(unitPath)
		if err != nil {
			log.Printf("failed to read binary path from unit file %s: %v", unitPath, err)
		} else {
			binaryPath = path
		}
		if !configPathExplicit {
			path, err := configPathFromSystemdUnit(unitPath)
			if err != nil {
				log.Printf("failed to read config path from unit file %s: %v", unitPath, err)
			} else {
				*configPath = path
			}
		}
	} else if !os.IsNotExist(err) {
		log.Fatalf("failed to stat unit file %s: %v", unitPath, err)
	}

	if _, err := exec.LookPath("systemctl"); err == nil {
		if unitExists {
			log.Printf("Removing systemd unit %s", unitPath)

			if err := runCmdLogged("systemctl", "stop", unitName); err != nil {
				log.Printf("systemctl stop failed for %s: %v", unitName, err)
			}
			if err := runCmdLogged("systemctl", "disable", unitName); err != nil {
				log.Printf("systemctl disable failed for %s: %v", unitName, err)
			}
			if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
				log.Fatalf("failed to remove unit file %s: %v", unitPath, err)
			}
			if err := runCmdLogged("systemctl", "daemon-reload"); err != nil {
				log.Fatalf("systemctl daemon-reload failed: %v", err)
			}
			if err := runCmdLogged("systemctl", "reset-failed", unitName); err != nil {
				if !isUnitNotLoadedError(err) {
					log.Printf("systemctl reset-failed failed for %s: %v", unitName, err)
				}
			}
		} else {
			log.Printf("No unit file found at %s; nothing to remove", unitPath)
		}
	} else {
		if unitExists {
			log.Printf("systemctl not found; removing unit file %s only", unitPath)
			if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
				log.Fatalf("failed to remove unit file %s: %v", unitPath, err)
			}
		} else {
			log.Printf("systemctl not found and no unit file at %s", unitPath)
		}
	}

	unregisterAgent(*configPath)

	if err := os.Remove(*configPath); err != nil && !os.IsNotExist(err) {
		log.Fatalf("failed to remove config file %s: %v", *configPath, err)
	}
	log.Printf("Removed config file %s", *configPath)

	if binaryPath == "" {
		exe, err := os.Executable()
		if err == nil {
			exe, err = filepath.EvalSymlinks(exe)
			if err == nil {
				binaryPath = exe
			}
		}
	}
	if binaryPath != "" {
		if err := os.Remove(binaryPath); err != nil && !os.IsNotExist(err) {
			log.Fatalf("failed to remove binary %s: %v", binaryPath, err)
		}
		log.Printf("Removed binary %s", binaryPath)
	}

	log.Printf("Uninstall completed for service %s", *serviceName)
}

func mustBeRoot() {
	if os.Geteuid() != 0 {
		log.Fatal("this command must be run as root (try: sudo ...)")
	}
}

func renderSystemdUnit(exePath, configPath string) string {
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
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

func binaryPathFromSystemdUnit(unitPath string) (string, error) {
	data, err := os.ReadFile(unitPath)
	if err != nil {
		return "", err
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "ExecStart=") {
			continue
		}

		cmdLine := strings.TrimSpace(strings.TrimPrefix(line, "ExecStart="))
		if cmdLine == "" {
			return "", fmt.Errorf("empty ExecStart")
		}

		if strings.HasPrefix(cmdLine, `"`) {
			end := strings.Index(cmdLine[1:], `"`)
			if end < 0 {
				return "", fmt.Errorf("invalid quoted ExecStart: %s", cmdLine)
			}
			return cmdLine[1 : 1+end], nil
		}

		fields := strings.Fields(cmdLine)
		if len(fields) == 0 {
			return "", fmt.Errorf("invalid ExecStart: %s", cmdLine)
		}
		return fields[0], nil
	}

	return "", fmt.Errorf("ExecStart not found")
}

func configPathFromSystemdUnit(unitPath string) (string, error) {
	data, err := os.ReadFile(unitPath)
	if err != nil {
		return "", err
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "ExecStart=") {
			continue
		}

		cmdLine := strings.TrimSpace(strings.TrimPrefix(line, "ExecStart="))
		if cmdLine == "" {
			return "", fmt.Errorf("empty ExecStart")
		}

		if strings.Contains(cmdLine, `--config "`) {
			parts := strings.SplitN(cmdLine, `--config "`, 2)
			if len(parts) == 2 {
				end := strings.Index(parts[1], `"`)
				if end >= 0 {
					return parts[1][:end], nil
				}
			}
		}

		fields := strings.Fields(cmdLine)
		for i := 0; i < len(fields); i++ {
			if fields[i] == "--config" && i+1 < len(fields) {
				return strings.Trim(fields[i+1], `"`), nil
			}
			if strings.HasPrefix(fields[i], "--config=") {
				return strings.Trim(strings.TrimPrefix(fields[i], "--config="), `"`), nil
			}
		}
		return "", fmt.Errorf("--config not found in ExecStart")
	}

	return "", fmt.Errorf("ExecStart not found")
}

func isUnitNotLoadedError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "not loaded")
}

func isFlagExplicitlySet(fs *flag.FlagSet, name string) bool {
	wasSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			wasSet = true
		}
	})
	return wasSet
}

func runCmdLogged(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if out.Len() > 0 {
		log.Printf("Ran command: %s %s:\n%s", name, strings.Join(args, " "), strings.TrimSpace(out.String()))
	}
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(out.String()))
	}
	return nil
}
