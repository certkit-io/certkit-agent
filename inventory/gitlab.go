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
	{"gitlab-pages", "pages_nginx", "pages_external_url"},
}

const gitlabConfigFile = "/etc/gitlab/gitlab.rb"

func (GitLabProvider) Collect() ([]api.InventoryItem, error) {
	// Read only gitlab.rb. Anything wrong here (file absent, unreadable, or
	// malformed) yields no items rather than failing the whole inventory run.
	data, err := utils.ReadFileBytes(gitlabConfigFile)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("Inventory read error for %s: %v", gitlabConfigFile, err)
		}
		return nil, nil
	}

	return parseGitLabConfig(data, gitlabConfigFile, nodeFQDN()), nil
}

func parseGitLabConfig(data []byte, path, fqdn string) []api.InventoryItem {
	// GitLab/Chef interpolates #{node['fqdn']} as the machine FQDN
	// (hostname -f), including inside explicit certificate paths.
	lines := strings.Split(strings.ReplaceAll(string(data), "#{node['fqdn']}", fqdn), "\n")

	// `false` is the only value that guarantees Let's Encrypt is off. true, unset,
	// and commented-out all mean GitLab may be auto-issuing/renewing the certs, so
	// in those cases we skip GitLab entirely rather than fight
	// `gitlab-ctl renew-le-certs`.
	if !strings.EqualFold(gitlabValue(lines, `letsencrypt\[['"]enable['"]\]\s*=\s*(true|false)`), "false") {
		log.Printf("GitLab Let's Encrypt is not explicitly disabled (letsencrypt['enable'] is not false); skipping GitLab certificates from inventory")
		return nil
	}

	items := make([]api.InventoryItem, 0)
	for _, svc := range gitlabServices {
		domain, ok := normalizeDomain(gitlabValue(lines, regexp.QuoteMeta(svc.urlKey)+`\s+['"]https://(.*?)['"]`))
		if !ok {
			continue // service has no https external_url
		}

		cert := gitlabValue(lines, regexp.QuoteMeta(svc.nginxKey)+`\[['"]ssl_certificate['"]\]\s*=\s*['"](.*?)['"]`)
		key := gitlabValue(lines, regexp.QuoteMeta(svc.nginxKey)+`\[['"]ssl_certificate_key['"]\]\s*=\s*['"](.*?)['"]`)

		// No explicit cert: GitLab serves a self-signed at its default path.
		if cert == "" {
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
