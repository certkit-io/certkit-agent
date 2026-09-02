//go:build windows

package install

import (
	"flag"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/certkit-io/certkit-agent/config"
)

// BootstrapConfigWindows creates the initial config file for MSI-based
// installs. Unlike InstallWindows it never touches the SCM, the event log
// source, or the registry (the MSI does this). It runs as a
// deferred custom action, so the registration key must arrive via --key:
// deferred actions do not inherit the installing user's environment.
func BootstrapConfigWindows(args []string, defaultServiceName string) {
	fs := flag.NewFlagSet("bootstrap-config", flag.ExitOnError)
	serviceName := fs.String("service-name", defaultServiceName, "windows service name")
	configPath := fs.String("config", DefaultWindowsConfigPath, "path to config.json")
	key := fs.String("key", "", "registration key used when creating a new config")
	fs.Parse(args)

	if !filepath.IsAbs(*configPath) {
		log.Fatalf("--config must be an absolute path: %s", *configPath)
	}

	if err := os.MkdirAll(filepath.Dir(*configPath), 0o755); err != nil {
		log.Fatalf("failed to create config dir: %v", err)
	}

	if _, err := os.Stat(*configPath); os.IsNotExist(err) {
		if strings.TrimSpace(*key) == "" && strings.TrimSpace(os.Getenv("REGISTRATION_KEY")) == "" {
			log.Fatalf("REGISTRATIONKEY is required for first install (no config at %s)", *configPath)
		}
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
}

// MsiCleanupWindows is the uninstall-time counterpart, run as a deferred
// custom action after StopServices on a true uninstall (never on upgrade).
// The MSI removes the service, event source, and files itself; this only
// unregisters the agent with the API (best effort) and removes the agent's
// data. Everything is best effort — a cleanup problem must never block or
// roll back an uninstall, so this always exits 0.
func MsiCleanupWindows(args []string) {
	fs := flag.NewFlagSet("msi-cleanup", flag.ExitOnError)
	configPath := fs.String("config", DefaultWindowsConfigPath, "path to config.json")
	fs.Parse(args)

	unregisterAgent(*configPath)

	if err := os.Remove(*configPath); err != nil && !os.IsNotExist(err) {
		log.Printf("Warning: failed to remove config file %s: %v", *configPath, err)
	} else {
		log.Printf("Removed config file %s", *configPath)
	}

	programData := os.Getenv("ProgramData")
	if programData != "" {
		programDataCertKit := filepath.Join(programData, "CertKit")
		if err := os.RemoveAll(programDataCertKit); err != nil {
			log.Printf("Warning: failed to remove ProgramData directory %s: %v", programDataCertKit, err)
		} else {
			log.Printf("Removed ProgramData directory %s", programDataCertKit)
		}
	}
}
