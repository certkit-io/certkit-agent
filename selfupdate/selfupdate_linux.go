//go:build !windows

package selfupdate

import (
	"fmt"
	"log"
	"os"
)

// replaceBinary replaces the currently running binary with the new binary at newPath.
// On Linux, this is an atomic rename. The running process keeps its open file
// descriptor to the old inode, which is safe.
func replaceBinary(newPath string) error {
	current, err := resolveExecutablePath()
	if err != nil {
		return err
	}

	if err := os.Chmod(newPath, 0o755); err != nil {
		return fmt.Errorf("chmod new binary: %w", err)
	}

	if err := os.Rename(newPath, current); err != nil {
		return fmt.Errorf("rename new binary into place: %w", err)
	}
	return nil
}

// TriggerRestart exits the process so systemd Restart=always restarts it with the new binary.
func TriggerRestart() {
	log.Printf("Self-update applied. Exiting for service manager restart...")
	os.Exit(0)
}
