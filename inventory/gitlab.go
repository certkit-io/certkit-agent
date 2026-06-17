package inventory

import (
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/certkit-io/certkit-agent/api"
	"github.com/certkit-io/certkit-agent/utils"
)

type GitLabProvider struct{}

func (GitLabProvider) Name() string {
	return "gitlab"
}

func (GitLabProvider) Collect() ([]api.InventoryItem, error) {
	configFiles, err := expandConfigGlobs([]string{
		"/etc/gitlab/gitlab.rb",
	})
	if err != nil {
		return nil, err
	}

	items := make([]api.InventoryItem, 0)
	for _, path := range configFiles {
		certs, keys, domains, err := parseGitLabConfig(path)
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
				Server:          "gitlab",
				ConfigPath:      path,
				CertificatePath: certs[i],
				KeyPath:         keys[i],
				Domains:         joinDomains(domains),
			})
		}
	}

	return items, nil
}

func parseGitLabConfig(path string) ([]string, []string, []string, error) {
	data, err := utils.ReadFileBytes(path)
	if err != nil {
		return nil, nil, nil, err
	}

	// Example: nginx['ssl_certificate'] = "/etc/gitlab/ssl/#{node['fqdn']}.crt"
	//      Or: nginx['ssl_certificate'] = "/etc/gitlab/ssl/gitlab.example.com.crt"
	reCert := regexp.MustCompile(`(?i)^\s*nginx\[['"]ssl_certificate['"]\] = ['"](.*?)['"]`)

	// Example: nginx['ssl_certificate_key'] = "/etc/gitlab/ssl/#{node['fqdn']}.key"
	//      Or: nginx['ssl_certificate_key'] = "/etc/gitlab/ssl/gitlab.example.com.key"
	reKey := regexp.MustCompile(`(?i)^\s*nginx\[['"]ssl_certificate_key['"]\] = ['"](.*?)['"]`)
	
	// Example: external_url 'https://gitlab.example.com'
	reServer := regexp.MustCompile(`(?i)^\s*external_url\s+['"]https:\/\/(.*?)['"]`)

	var certs []string
	var keys []string
	var domains []string

	// Get the domain first, because it may be needed in the cert and key path
	// The `external_url` line SHOULD come first, so in theory the double-loop isn't needed,
	// but who knows maybe some user is going to copy/paste the `nginx['ssl_certificate']`
	// and `nginx['ssl_certificate_key']` lines to the top of the file for some reason
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		if match := reServer.FindStringSubmatch(line); len(match) == 2 {
			if domain, ok := normalizeDomain(match[1]); ok {
				domains = append(domains, domain)
				break
			}
		}
	}

	// Bail if we didn't find a domain
	if len(domains) == 0 {
		return certs, keys, domains, errors.New("Could not find/parse 'external_url' value")
	}

	// Now get the certs and keys
	for _, line := range lines {
		if line == "" {
			continue
		}

		// Default nginx['ssl_certificate'] and nginx['ssl_certificate_key'] lines
		// use a variable for the domain name as part of the filename, so we do a
		// string replacement to ensure we don't return the variable placeholder
		line := strings.ReplaceAll(line, "#{node['fqdn']}", domains[0])

		if match := reCert.FindStringSubmatch(line); len(match) == 2 {
			certs = append(certs, cleanConfigValue(match[1]))
			continue
		}
		if match := reKey.FindStringSubmatch(line); len(match) == 2 {
			keys = append(keys, cleanConfigValue(match[1]))
			continue
		}
	}

	// Default behaviour is for GitLab to use /etc/gitlab/ssl/<domain>.crt
	// and /etc/gitlab/ssl/<domain>.key, so if we didn't parse any certs or
	// keys above then we'll assume that's what the filenames should be
	if len(certs) == 0 {
		certs = append(certs, fmt.Sprintf("/etc/gitlab/ssl/%s.crt", domains[0]))
	}
	if len(keys) == 0 {
		keys = append(keys, fmt.Sprintf("/etc/gitlab/ssl/%s.key", domains[0]))
	}

	return certs, keys, domains, nil
}
