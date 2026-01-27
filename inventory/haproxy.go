package inventory

import (
	"log"
	"strings"

	"github.com/certkit-io/certkit-agent/api"
	"github.com/certkit-io/certkit-agent/utils"
)

type HaproxyProvider struct{}

func (HaproxyProvider) Name() string {
	return "haproxy"
}

func (HaproxyProvider) Collect() ([]api.InventoryItem, error) {
	configFiles, err := expandConfigGlobs([]string{
		"/etc/haproxy/haproxy.cfg",
		"/etc/haproxy/conf.d/*.cfg",
		"/etc/haproxy/conf.d/*.conf",
		"/usr/local/etc/haproxy/haproxy.cfg",
		"/usr/local/etc/haproxy/conf.d/*.cfg",
		"/usr/local/etc/haproxy/conf.d/*.conf",
	})
	if err != nil {
		return nil, err
	}

	items := make([]api.InventoryItem, 0)
	for _, path := range configFiles {
		certs, keys, domains, err := parseHaproxyConfig(path)
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
				Server:          "haproxy",
				ConfigPath:      path,
				CertificatePath: certs[i],
				KeyPath:         keys[i],
				Domains:         joinDomains(domains),
			})
		}
	}

	return items, nil
}

func parseHaproxyConfig(path string) ([]string, []string, []string, error) {
	data, err := utils.ReadFileBytes(path)
	if err != nil {
		return nil, nil, nil, err
	}

	var certs []string
	var keys []string
	var domains []string

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		trimmed := stripHaproxyComment(line)
		if trimmed == "" {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) == 0 {
			continue
		}
		for i := 0; i < len(fields)-1; i++ {
			token := fields[i]
			if strings.EqualFold(token, "crt") {
				certPath := cleanConfigValue(fields[i+1])
				if certPath != "" {
					certs = append(certs, certPath)
					keys = append(keys, certPath)
				}
				continue
			}
			if strings.EqualFold(token, "crt-list") {
				listPath := cleanConfigValue(fields[i+1])
				if listPath == "" {
					continue
				}
				listCerts, err := parseHaproxyCrtList(listPath)
				if err != nil {
					return nil, nil, nil, err
				}
				for _, certPath := range listCerts {
					certs = append(certs, certPath)
					keys = append(keys, certPath)
				}
			}
		}

		domains = append(domains, parseHaproxyDomains(trimmed)...)
	}

	return certs, keys, domains, nil
}

func parseHaproxyCrtList(path string) ([]string, error) {
	data, err := utils.ReadFileBytes(path)
	if err != nil {
		return nil, err
	}

	var certs []string
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		trimmed := stripHaproxyComment(line)
		if trimmed == "" {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) == 0 {
			continue
		}
		certPath := cleanConfigValue(fields[0])
		if certPath != "" {
			certs = append(certs, certPath)
		}
	}

	return certs, nil
}

func parseHaproxyDomains(line string) []string {
	lower := strings.ToLower(line)
	if !strings.Contains(lower, "hdr(host") &&
		!strings.Contains(lower, "ssl_fc_sni") &&
		!strings.Contains(lower, "req.ssl_sni") {
		return nil
	}

	var domains []string
	fields := strings.Fields(line)
	for _, field := range fields {
		if domain, ok := normalizeDomain(field); ok {
			domains = append(domains, domain)
		}
	}
	return domains
}

func stripHaproxyComment(line string) string {
	if idx := strings.Index(line, "#"); idx >= 0 {
		line = line[:idx]
	}
	return strings.TrimSpace(line)
}
