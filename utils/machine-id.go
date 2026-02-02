//go:build !windows

package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const (
	// Change this to namespace identities per app
	identityNamespace = "certkit-agent"
)

// GetStableMachineID returns a stable, unique identifier regardless of environment.
func GetStableMachineID() (string, error) {
	// 1. Persistent ID (best)
	if id, err := loadPersistentID(); err == nil {
		return id, nil
	}

	// 2. Linux machine-id (host-level)
	if id, err := readAndHash("/etc/machine-id"); err == nil {
		return id, nil
	}

	// 3. Container cgroup ID (container-level)
	if id, err := containerID(); err == nil {
		return id, nil
	}

	// 4. Absolute fallback: generate & persist
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

func readAndHash(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "", errors.New("empty id source")
	}
	return hashWithNamespace(s), nil
}

func containerID() (string, error) {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(b), "\n")
	for _, line := range lines {
		if strings.Contains(line, "/docker/") ||
			strings.Contains(line, "/kubepods/") ||
			strings.Contains(line, "/containerd/") {

			parts := strings.Split(line, "/")
			id := parts[len(parts)-1]
			if len(id) >= 12 {
				return hashWithNamespace(id), nil
			}
		}
	}
	return "", errors.New("no container id found")
}

func hashWithNamespace(value string) string {
	sum := sha256.Sum256([]byte(value + ":" + identityNamespace))
	return hex.EncodeToString(sum[:])
}

func persistentIDPath() string {
	// Override with env if desired
	if p := os.Getenv("AGENT_ID_PATH"); p != "" {
		return p
	}

	// Linux / containers
	if os.Geteuid() == 0 {
		return "/var/lib/certkit/agent-id"
	}

	// User mode fallback
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".certkit", "agent-id")
}
