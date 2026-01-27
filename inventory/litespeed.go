package inventory

import (
	"log"
	"regexp"
	"strings"

	"github.com/certkit-io/certkit-agent/api"
	"github.com/certkit-io/certkit-agent/utils"
)

type LitespeedProvider struct{}

func (LitespeedProvider) Name() string {
	return "litespeed"
}

func (LitespeedProvider) Collect() ([]api.InventoryItem, error) {
	configFiles, err := expandConfigGlobs([]string{
		"/usr/local/lsws/conf/httpd_config.conf",
		"/usr/local/lsws/conf/vhosts/*/vhconf.conf",
		"/etc/lsws/conf/httpd_config.conf",
		"/etc/lsws/conf/vhosts/*/vhconf.conf",
	})
	if err != nil {
		return nil, err
	}

	items := make([]api.InventoryItem, 0)
	for _, path := range configFiles {
		certs, keys, domains, err := parseLitespeedConfig(path)
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
				Server:          "litespeed",
				ConfigPath:      path,
				CertificatePath: certs[i],
				KeyPath:         keys[i],
				Domains:         joinDomains(domains),
			})
		}
	}

	return items, nil
}

func parseLitespeedConfig(path string) ([]string, []string, []string, error) {
	data, err := utils.ReadFileBytes(path)
	if err != nil {
		return nil, nil, nil, err
	}

	reCert := regexp.MustCompile(`(?i)^\s*sslCertFile\s+(.+)$`)
	reKey := regexp.MustCompile(`(?i)^\s*sslKeyFile\s+(.+)$`)
	reDomain := regexp.MustCompile(`(?i)^\s*vhDomain\s+(.+)$`)

	var certs []string
	var keys []string
	var domains []string

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		trimmed := stripLitespeedComment(line)
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
		if match := reDomain.FindStringSubmatch(trimmed); len(match) == 2 {
			fields := strings.FieldsFunc(match[1], func(r rune) bool {
				return r == ',' || r == ' ' || r == '\t'
			})
			for _, field := range fields {
				if domain, ok := normalizeDomain(field); ok {
					domains = append(domains, domain)
				}
			}
		}
	}

	return certs, keys, domains, nil
}

func stripLitespeedComment(line string) string {
	if idx := strings.Index(line, "#"); idx >= 0 {
		line = line[:idx]
	}
	return strings.TrimSpace(line)
}
