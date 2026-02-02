//go:build linux

package inventory

import (
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/certkit-io/certkit-agent/api"
)

type DockerProvider struct{}

func (DockerProvider) Name() string {
	return "docker"
}

func (DockerProvider) Collect() ([]api.InventoryItem, error) {
	if !isContainerEnvironment() {
		return nil, nil
	}

	mounts, err := dockerMounts()
	if err != nil {
		return nil, err
	}

	items := make([]api.InventoryItem, 0)
	for _, mount := range mounts {
		mountItems, err := collectMountCerts(mount)
		if err != nil {
			log.Printf("Docker inventory scan error for %s: %v", mount, err)
			continue
		}
		items = append(items, mountItems...)
	}

	return items, nil
}

func collectMountCerts(mount string) ([]api.InventoryItem, error) {
	certByBase := make(map[string]string)
	keyByBase := make(map[string]string)
	standalone := make([]string, 0)

	err := filepath.WalkDir(mount, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		base := strings.TrimSuffix(path, filepath.Ext(path))
		switch ext {
		case ".crt", ".pem":
			if _, ok := certByBase[base]; !ok {
				certByBase[base] = path
			}
		case ".key":
			if _, ok := keyByBase[base]; !ok {
				keyByBase[base] = path
			}
		case ".pfx", ".p12", ".jks":
			standalone = append(standalone, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	server := fmt.Sprintf("docker:%s", mount)
	items := make([]api.InventoryItem, 0, len(certByBase)+len(standalone))
	for base, certPath := range certByBase {
		items = append(items, api.InventoryItem{
			Server:          server,
			ConfigPath:      mount,
			CertificatePath: certPath,
			KeyPath:         keyByBase[base],
		})
	}
	for _, path := range standalone {
		items = append(items, api.InventoryItem{
			Server:          server,
			ConfigPath:      mount,
			CertificatePath: path,
			KeyPath:         "",
		})
	}

	return items, nil
}

func dockerMounts() ([]string, error) {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}

	seen := make(map[string]struct{})
	mounts := make([]string, 0)
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Split(line, " - ")
		if len(parts) < 2 {
			continue
		}
		fields := strings.Fields(parts[0])
		if len(fields) < 5 {
			continue
		}
		mountPoint := unescapeMountPath(fields[4])
		if mountPoint == "/" {
			continue
		}
		if strings.HasPrefix(mountPoint, "/proc") ||
			strings.HasPrefix(mountPoint, "/sys") ||
			strings.HasPrefix(mountPoint, "/dev") {
			continue
		}
		if !isDockerMountWhitelisted(mountPoint) {
			continue
		}
		if _, ok := seen[mountPoint]; ok {
			continue
		}
		seen[mountPoint] = struct{}{}
		mounts = append(mounts, mountPoint)
	}

	return mounts, nil
}

func isContainerEnvironment() bool {
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

func isDockerMountWhitelisted(mountPoint string) bool {
	for _, prefix := range dockerMountWhitelist() {
		if mountPoint == prefix || strings.HasPrefix(mountPoint, prefix+"/") {
			return true
		}
	}
	return false
}

func dockerMountWhitelist() []string {
	return []string{
		"/certs",
		"/cert",
		"/ssl",
		"/certificates",
		"/etc/ssl",
		"/etc/ssl/certs",
		"/etc/ssl/private",
		"/etc/pki",
		"/etc/pki/tls",
		"/etc/pki/tls/certs",
		"/etc/pki/tls/private",
		"/etc/letsencrypt",
		"/etc/letsencrypt/live",
		"/etc/letsencrypt/archive",
		"/etc/nginx",
		"/etc/apache2",
		"/etc/httpd",
		"/usr/local/etc",
		"/usr/local/etc/ssl",
		"/run/secrets",
		"/var/run/secrets",
		"/secrets",
		"/config",
		"/configs",
		"/data",
		"/mnt",
		"/shared",
		"/volumes",
		"/opt",
		"/srv",
	}
}

func unescapeMountPath(value string) string {
	var b strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] == '\\' && i+3 < len(value) {
			if isOctal(value[i+1]) && isOctal(value[i+2]) && isOctal(value[i+3]) {
				octal := value[i+1 : i+4]
				var v byte
				for j := 0; j < 3; j++ {
					v = (v * 8) + (octal[j] - '0')
				}
				b.WriteByte(v)
				i += 3
				continue
			}
		}
		b.WriteByte(value[i])
	}
	return b.String()
}

func isOctal(c byte) bool {
	return c >= '0' && c <= '7'
}
