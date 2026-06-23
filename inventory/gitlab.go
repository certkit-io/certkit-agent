package inventory

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/certkit-io/certkit-agent/api"
	"github.com/certkit-io/certkit-agent/utils"
)

type GitLabProvider struct{}

func (GitLabProvider) Name() string {
	return "gitlab"
}

// gitlabService is a bundled GitLab service that can terminate TLS in the
// Omnibus nginx. Each is keyed off its own external_url and
// *_nginx['ssl_certificate*'] settings in /etc/gitlab/gitlab.rb and reported as
// its own inventory item.
type gitlabService struct {
	server   string
	nginxKey string
	urlKey   string
}

var gitlabServices = []gitlabService{
	{"gitlab", "nginx", "external_url"},
	{"gitlab-registry", "registry_nginx", "registry_external_url"},
	{"gitlab-mattermost", "mattermost_nginx", "mattermost_external_url"},
	{"gitlab-pages", "pages_nginx", "pages_external_url"},
}

func (GitLabProvider) Collect() ([]api.InventoryItem, error) {
	configFiles, err := expandConfigGlobs([]string{"/etc/gitlab/gitlab.rb"})
	if err != nil {
		return nil, err
	}

	items := make([]api.InventoryItem, 0)
	for _, path := range configFiles {
		data, err := utils.ReadFileBytes(path)
		if err != nil {
			log.Printf("Inventory read error for %s: %v", path, err)
			continue
		}
		items = append(items, parseGitLabConfig(data, path, nodeFQDN())...)
	}

	return items, nil
}

func parseGitLabConfig(data []byte, path, fqdn string) []api.InventoryItem {
	// GitLab interpolates #{node['fqdn']} (the machine FQDN, hostname -f) into its
	// default cert paths, so resolve it for the whole file up front.
	lines := strings.Split(strings.ReplaceAll(string(data), "#{node['fqdn']}", fqdn), "\n")

	// GitLab auto-renews its default cert via Let's Encrypt unless explicitly
	// disabled; skip those so certkit doesn't fight `gitlab-ctl renew-le-certs`.
	leDisabled := strings.EqualFold(gitlabValue(lines, `letsencrypt\[['"]enable['"]\]\s*=\s*(true|false)`), "false")

	items := make([]api.InventoryItem, 0)
	for _, svc := range gitlabServices {
		domain, ok := normalizeDomain(gitlabValue(lines, regexp.QuoteMeta(svc.urlKey)+`\s+['"]https://(.*?)['"]`))
		if !ok {
			continue // service has no https external_url
		}

		cert := gitlabValue(lines, regexp.QuoteMeta(svc.nginxKey)+`\[['"]ssl_certificate['"]\]\s*=\s*['"](.*?)['"]`)
		key := gitlabValue(lines, regexp.QuoteMeta(svc.nginxKey)+`\[['"]ssl_certificate_key['"]\]\s*=\s*['"](.*?)['"]`)

		if cert == "" {
			if !leDisabled {
				continue // GitLab-managed via Let's Encrypt
			}
			// No explicit cert: GitLab serves a self-signed at its default path.
			cert = fmt.Sprintf("/etc/gitlab/ssl/%s.crt", fqdn)
		}
		if key == "" {
			key = fmt.Sprintf("/etc/gitlab/ssl/%s.key", fqdn)
		}

		items = append(items, api.InventoryItem{
			Server:          svc.server,
			ConfigPath:      path,
			CertificatePath: cert,
			KeyPath:         key,
			Domains:         domain,
		})
	}

	return items
}

// gitlabValue returns the first capture group of pattern across lines, anchored
// at the start of a line and case-insensitive, or "" if nothing matches.
func gitlabValue(lines []string, pattern string) string {
	re := regexp.MustCompile(`(?i)^\s*` + pattern)
	for _, line := range lines {
		if m := re.FindStringSubmatch(line); len(m) == 2 {
			return m[1]
		}
	}
	return ""
}

// nodeFQDN resolves the machine FQDN the way GitLab/Chef does (node['fqdn']),
// falling back to the kernel hostname.
func nodeFQDN() string {
	if out, err := exec.Command("hostname", "-f").Output(); err == nil {
		if fqdn := strings.TrimSpace(string(out)); fqdn != "" {
			return fqdn
		}
	}
	host, _ := os.Hostname()
	return host
}
