package inventory

import (
	"regexp"
	"strconv"
	"strings"
)

var fqdnRegex = regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

func joinDomains(domains []string) string {
	if len(domains) == 0 {
		return ""
	}
	seen := make(map[string]struct{}, len(domains))
	unique := make([]string, 0, len(domains))
	for _, domain := range domains {
		if domain == "" {
			continue
		}
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}
		unique = append(unique, domain)
	}
	return strings.Join(unique, ",")
}

func normalizeDomain(token string) (string, bool) {
	token = strings.TrimSpace(token)
	token = strings.Trim(token, "\"';")
	if token == "" {
		return "", false
	}
	token = strings.Trim(token, ",")
	token = strings.TrimSuffix(token, ";")
	token = stripPort(token)
	if strings.HasPrefix(token, "*.") {
		token = strings.TrimPrefix(token, "*.")
	}
	if token == "" || strings.Contains(token, "*") {
		return "", false
	}
	if !fqdnRegex.MatchString(token) {
		return "", false
	}
	return strings.ToLower(token), true
}

func stripPort(value string) string {
	host, port, found := strings.Cut(value, ":")
	if !found {
		return value
	}
	if host == "" || port == "" {
		return value
	}
	if _, err := strconv.Atoi(port); err != nil {
		return value
	}
	return host
}
