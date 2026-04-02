//go:build windows

package selfupdate

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// replaceBinary replaces the currently running binary with the new binary at newPath.
// On Windows, a running .exe cannot be overwritten but CAN be renamed. The strategy is:
// 1. Rename running exe to .old.exe
// 2. Move new binary to the original path
// If step 2 fails, .old.exe is renamed back to restore the original state.
func replaceBinary(newPath string) error {
	current, err := resolveExecutablePath()
	if err != nil {
		return err
	}

	ext := filepath.Ext(current)
	oldPath := strings.TrimSuffix(current, ext) + ".old" + ext

	os.Remove(oldPath)

	if err := os.Rename(current, oldPath); err != nil {
		return fmt.Errorf("rename running binary to .old: %w", err)
	}

	if err := os.Rename(newPath, current); err != nil {
		if restoreErr := os.Rename(oldPath, current); restoreErr != nil {
			return fmt.Errorf("move new binary failed (%w) AND restore failed (%v)", err, restoreErr)
		}
		return fmt.Errorf("move new binary into place: %w (original restored)", err)
	}
	return nil
}

// TriggerRestart exits the process so the SCM recovery policy restarts the service.
// On Windows, the SCM recovery is configured to restart on failure (non-zero exit).
func TriggerRestart() {
	log.Printf("Self-update applied. Exiting for service manager restart...")
	os.Exit(1)
}
