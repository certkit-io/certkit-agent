package inventory

import (
	"log"
	"regexp"
	"strings"

	"github.com/certkit-io/certkit-agent/api"
	"github.com/certkit-io/certkit-agent/utils"
)

type NginxProvider struct{}

func (NginxProvider) Name() string {
	return "nginx"
}

func (NginxProvider) Collect() ([]api.InventoryItem, error) {
	configFiles, err := expandConfigGlobs([]string{
		"/etc/nginx/nginx.conf",
		"/etc/nginx/conf.d/*.conf",
		"/etc/nginx/sites-enabled/*",
		"/etc/nginx/sites-available/*",
		"/usr/local/etc/nginx/nginx.conf",
		"/usr/local/etc/nginx/conf.d/*.conf",
	})
	if err != nil {
		return nil, err
	}

	items := make([]api.InventoryItem, 0)
	for _, path := range configFiles {
		certs, keys, domains, err := parseNginxConfig(path)
		if err != nil {
			log.Printf("Inventory parse error for %s: %v", path, err)
			continue
		}

		pairs := len(certs)
		if len(keys) < pairs {
			pairs = len(keys)
		}
		for i := 0; i < pairs; i++ {
			items = append(items, api.InventoryItem{
				Server:          "nginx",
				ConfigPath:      path,
				CertificatePath: certs[i],
				KeyPath:         keys[i],
				Domains:         joinDomains(domains),
			})
		}
	}

	return items, nil
}

func parseNginxConfig(path string) ([]string, []string, []string, error) {
	data, err := utils.ReadFileBytes(path)
	if err != nil {
		return nil, nil, nil, err
	}

	reCert := regexp.MustCompile(`(?i)^\s*ssl_certificate\s+([^;]+);`)
	reKey := regexp.MustCompile(`(?i)^\s*ssl_certificate_key\s+([^;]+);`)
	reServer := regexp.MustCompile(`(?i)^\s*server_name\s+([^;]+);`)

	var certs []string
	var keys []string
	var domains []string

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		trimmed := stripNginxComment(line)
		if trimmed == "" {
			continue
		}
		if match := reCert.FindStringSubmatch(trimmed); len(match) == 2 {
			certs = append(certs, cleanConfigValue(match[1]))
			continue
		}
		if match := reKey.FindStringSubmatch(trimmed); len(match) == 2 {
			keys = append(keys, cleanConfigValue(match[1]))
			continue
		}
		if match := reServer.FindStringSubmatch(trimmed); len(match) == 2 {
			fields := strings.Fields(match[1])
			for _, field := range fields {
				if domain, ok := normalizeDomain(field); ok {
					domains = append(domains, domain)
				}
			}
		}
	}

	return certs, keys, domains, nil
}

func stripNginxComment(line string) string {
	if idx := strings.Index(line, "#"); idx >= 0 {
		line = line[:idx]
	}
	return strings.TrimSpace(line)
}
