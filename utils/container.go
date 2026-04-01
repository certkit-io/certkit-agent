//go:build !windows

package utils

import (
	"os"
	"strings"
)

// IsContainerEnvironment reports whether the process is running inside a
// container (Docker, Kubernetes, Podman, etc.).
func IsContainerEnvironment() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		return true
	}
	data, err := os.ReadFile("/proc/1/cgroup")
	if err != nil {
		return false
	}
	content := string(data)
	return strings.Contains(content, "docker") ||
		strings.Contains(content, "kubepods") ||
		strings.Contains(content, "containerd") ||
		strings.Contains(content, "podman") ||
		strings.Contains(content, "libpod")
}
