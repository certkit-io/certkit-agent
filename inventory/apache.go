package inventory

import (
	"log"
	"regexp"
	"runtime"
	"strings"

	"github.com/certkit-io/certkit-agent/api"
	"github.com/certkit-io/certkit-agent/utils"
)

type ApacheProvider struct{}

func (ApacheProvider) Name() string {
	return "apache"
}

func (ApacheProvider) Collect() ([]api.InventoryItem, error) {
	configFiles, err := expandConfigGlobs(apacheConfigGlobs())
	if err != nil {
		return nil, err
	}

	items := make([]api.InventoryItem, 0)
	for _, path := range configFiles {
		certs, keys, chains, domains, err := parseApacheConfig(path)
		if err != nil {
			log.Printf("Inventory parse error for %s: %v", path, err)
			continue
		}

		pairs := len(certs)
		if len(keys) < pairs {
			pairs = len(keys)
		}
		for i := 0; i < pairs; i++ {
			chainPath := ""
			if i < len(chains) {
				chainPath = chains[i]
			}
			items = append(items, api.InventoryItem{
				Server:          "apache",
				ConfigPath:      path,
				CertificatePath: certs[i],
				KeyPath:         keys[i],
				ChainPath:       chainPath,
				Domains:         joinDomains(domains),
			})
		}
	}

	return items, nil
}

func apacheConfigGlobs() []string {
	if runtime.GOOS == "windows" {
		return []string{
			`C:\Apache24\conf\httpd.conf`,
			`C:\Apache24\conf\extra\*.conf`,
			`C:\Apache24\conf\sites-enabled\*`,
			`C:\Apache2\conf\httpd.conf`,
			`C:\Apache2\conf\extra\*.conf`,
			`C:\Apache2\conf\sites-enabled\*`,
			`C:\Apache\conf\httpd.conf`,
			`C:\Apache\conf\extra\*.conf`,
			`C:\Program Files\Apache Group\Apache2\conf\httpd.conf`,
			`C:\Program Files\Apache Group\Apache2\conf\extra\*.conf`,
			`C:\Program Files\Apache24\conf\httpd.conf`,
			`C:\Program Files\Apache24\conf\extra\*.conf`,
			`C:\httpd\conf\httpd.conf`,
			`C:\httpd\conf\extra\*.conf`,
		}
	}

	return []string{
		"/etc/apache2/apache2.conf",
		"/etc/apache2/conf-enabled/*.conf",
		"/etc/apache2/sites-enabled/*",
		"/etc/apache2/sites-available/*",
		"/etc/httpd/conf/httpd.conf",
		"/etc/httpd/conf.d/*.conf",
		"/usr/local/etc/apache24/httpd.conf",
	}
}

func parseApacheConfig(path string) ([]string, []string, []string, []string, error) {
	data, err := utils.ReadFileBytes(path)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	reCert := regexp.MustCompile(`(?i)^\s*SSLCertificateFile\s+(.+)$`)
	reKey := regexp.MustCompile(`(?i)^\s*SSLCertificateKeyFile\s+(.+)$`)
	reChain := regexp.MustCompile(`(?i)^\s*SSLCertificateChainFile\s+(.+)$`)
	reServerName := regexp.MustCompile(`(?i)^\s*ServerName\s+(.+)$`)
	reServerAlias := regexp.MustCompile(`(?i)^\s*ServerAlias\s+(.+)$`)

	var certs []string
	var keys []string
	var chains []string
	var domains []string

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		trimmed := stripApacheComment(line)
		if trimmed == "" {
			continue
		}
		if match := reCert.FindStringSubmatch(trimmed); len(match) == 2 {
			certs = append(certs, normalizeApachePath(cleanConfigValue(match[1])))
			continue
		}
		if match := reKey.FindStringSubmatch(trimmed); len(match) == 2 {
			keys = append(keys, normalizeApachePath(cleanConfigValue(match[1])))
			continue
		}
		if match := reChain.FindStringSubmatch(trimmed); len(match) == 2 {
			chains = append(chains, normalizeApachePath(cleanConfigValue(match[1])))
			continue
		}
		if match := reServerName.FindStringSubmatch(trimmed); len(match) == 2 {
			for _, field := range strings.Fields(match[1]) {
				if domain, ok := normalizeDomain(field); ok {
					domains = append(domains, domain)
				}
			}
			continue
		}
		if match := reServerAlias.FindStringSubmatch(trimmed); len(match) == 2 {
			for _, field := range strings.Fields(match[1]) {
				if domain, ok := normalizeDomain(field); ok {
					domains = append(domains, domain)
				}
			}
		}
	}

	return certs, keys, chains, domains, nil
}

func normalizeApachePath(value string) string {
	if runtime.GOOS != "windows" {
		return value
	}
	value = strings.ReplaceAll(value, "/", `\`)
	value = strings.ReplaceAll(value, `\\`, `\`)
	return value
}

func stripApacheComment(line string) string {
	if idx := strings.Index(line, "#"); idx >= 0 {
		line = line[:idx]
	}
	return strings.TrimSpace(line)
}
