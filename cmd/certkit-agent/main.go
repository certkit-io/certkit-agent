// certkit-agent main.go
//
// Minimal CLI with:
//
//	certkit-agent install   -> writes a systemd unit file and enables/starts it
//	certkit-agent uninstall -> removes service registration
//	certkit-agent run       -> stubbed daemon loop (logs for now)
//
// Build:
//
//	go build -o certkit-agent .
//
// Install (as root):
//
//	./certkit-agent install
//
// Run (for debugging):
//
//	./certkit-agent run
package main

import (
	"log"
	"os"

	"github.com/certkit-io/certkit-agent/config"
)

const defaultServiceName = "certkit-agent"

var (
	// Set via -ldflags "-X main.version=..."
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func Version() config.VersionInfo {
	return config.VersionInfo{
		Version: version,
		Commit:  commit,
		Date:    date,
	}
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags | log.LUTC)

	if len(os.Args) < 2 {
		usageAndExit()
	}

	switch os.Args[1] {
	case "install":
		installCmd(os.Args[2:])
	case "uninstall":
		uninstallCmd(os.Args[2:])
	case "run":
		runCmd(os.Args[2:])
	default:
		usageAndExit()
	}
}
