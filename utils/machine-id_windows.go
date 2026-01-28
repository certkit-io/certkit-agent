//go:build windows

package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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

//
// ---- helpers ------------------------------------------------------------
//

func loadPersistentID() (string, error) {
	path := persistentIDPath()
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

func persistentIDPath() string {
	if p := os.Getenv("AGENT_ID_PATH"); p != "" {
		return p
	}

	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}

	return filepath.Join(programData, "CertKit", "agent-id")
}
