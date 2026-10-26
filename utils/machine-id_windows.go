//go:build windows

package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const (
	identityNamespace = "certkit-agent"
)

// GetStableMachineID returns a stable, unique identifier regardless of environment.
func GetStableMachineID() (string, error) {
	// 1. Persistent ID (best)
	if id, err := loadPersistentID(); err == nil {
		return id, nil
	}

	// 2. Windows MachineGuid (host-level)
	if id, err := readMachineGuid(); err == nil {
		return id, nil
	}

	// 3. Absolute fallback: generate & persist
	return generateAndPersistID()
}

// MoveLegacyMachineIDFile moves the machine ID file that older versions kept at
// the root of %ProgramData%\CertKit, a folder other CertKit products share, into
// the agent's own folder. Self-update only swaps the exe, so the running service
// moves it.
func MoveLegacyMachineIDFile() error {
	if os.Getenv("AGENT_ID_PATH") != "" {
		return nil
	}

	legacyPath := legacyPersistentIDPath()
	id, err := readPersistentID(legacyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read %s: %w", legacyPath, err)
	}

	// Write the new file before deleting the old one, rather than renaming:
	// lookups check the old location first, so the ID stays readable throughout.
	// A different ID already at newPath is replaced, since the old one is in use.
	newPath := persistentIDPath()
	existing, _ := readPersistentID(newPath)
	if existing != id {
		if err := os.MkdirAll(filepath.Dir(newPath), 0700); err != nil {
			return fmt.Errorf("create directory %s: %w", filepath.Dir(newPath), err)
		}
		if err := os.WriteFile(newPath, []byte(id), 0600); err != nil {
			return fmt.Errorf("write %s: %w", newPath, err)
		}
	}
	if err := os.Remove(legacyPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove %s: %w", legacyPath, err)
	}
	log.Printf("Moved machine ID file %s to %s", legacyPath, newPath)
	return nil
}

//
// ---- helpers ------------------------------------------------------------
//

func loadPersistentID() (string, error) {
	// Older versions kept the file at the root of %ProgramData%\CertKit. Check
	// there first: it is the ID in use until the service moves it, and the move
	// writes the new file before deleting the old one, so a lookup during the
	// move still finds the ID.
	if os.Getenv("AGENT_ID_PATH") == "" {
		if id, err := readPersistentID(legacyPersistentIDPath()); err == nil {
			return id, nil
		}
	}
	return readPersistentID(persistentIDPath())
}

func readPersistentID(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(b))
	if id == "" {
		return "", errors.New("empty persisted id")
	}
	return id, nil
}

func generateAndPersistID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	id := hashWithNamespace(hex.EncodeToString(b))

	path := persistentIDPath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return "", err
	}

	if err := os.WriteFile(path, []byte(id), 0600); err != nil {
		return "", err
	}

	return id, nil
}

func readMachineGuid() (string, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer key.Close()

	guid, _, err := key.GetStringValue("MachineGuid")
	if err != nil {
		return "", err
	}
	guid = strings.TrimSpace(guid)
	if guid == "" {
		return "", errors.New("empty MachineGuid")
	}
	return hashWithNamespace(guid), nil
}

func hashWithNamespace(value string) string {
	sum := sha256.Sum256([]byte(value + ":" + identityNamespace))
	return hex.EncodeToString(sum[:])
}

// persistentIDPath is the machine ID file in the agent's own folder, next to the
// default config.
func persistentIDPath() string {
	if p := os.Getenv("AGENT_ID_PATH"); p != "" {
		return p
	}
	return filepath.Join(certkitProgramDataDir(), "certkit-agent", "agent-id")
}

// legacyPersistentIDPath is where older versions kept the machine ID file.
func legacyPersistentIDPath() string {
	return filepath.Join(certkitProgramDataDir(), "agent-id")
}

func certkitProgramDataDir() string {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	return filepath.Join(programData, "CertKit")
}
