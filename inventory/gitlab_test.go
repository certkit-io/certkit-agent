package inventory

import (
	"testing"

	"github.com/certkit-io/certkit-agent/api"
)

const (
	gitlabConfigPath = gitlabConfigFile
	testFQDN         = "host01.internal.example.com"
	leOff            = "letsencrypt['enable'] = false\n"
)

func TestParseGitLabConfig(t *testing.T) {
	tests := []struct {
		name   string
		config string
		want   []api.InventoryItem
	}{
		// --- Let's Encrypt gate: only an explicit `false` allows discovery ------
		{
			name:   "lets encrypt true is skipped even with an explicit cert",
			config: "external_url 'https://gitlab.example.com'\nletsencrypt['enable'] = true\n" + explicitMainCert,
			want:   nil,
		},
		{
			name:   "lets encrypt unset is skipped even with an explicit cert",
			config: "external_url 'https://gitlab.example.com'\n" + explicitMainCert,
			want:   nil,
		},
		{
			name:   "lets encrypt commented out is skipped",
			config: "external_url 'https://gitlab.example.com'\n# letsencrypt['enable'] = false\n" + explicitMainCert,
			want:   nil,
		},

		// --- letsencrypt['enable'] = false: discovery is allowed ---------------
		{
			name:   "false with no cert falls back to the MACHINE FQDN self-signed path",
			config: leOff + "external_url 'https://gitlab.example.com'\n",
			want: []api.InventoryItem{
				gitlabItem("gitlab", "/etc/gitlab/ssl/host01.internal.example.com.crt", "/etc/gitlab/ssl/host01.internal.example.com.key", "gitlab.example.com"),
			},
		},
		{
			name:   "false with node fqdn interpolation uses the machine FQDN",
			config: leOff + "external_url 'https://gitlab.example.com'\n" + explicitMainCert,
			want: []api.InventoryItem{
				gitlabItem("gitlab", "/etc/gitlab/ssl/host01.internal.example.com.crt", "/etc/gitlab/ssl/host01.internal.example.com.key", "gitlab.example.com"),
			},
		},
		{
			name: "false with explicit literal paths and single quotes",
			config: leOff + `external_url "https://gitlab.example.com"` + "\n" +
				`nginx['ssl_certificate'] = '/secure/certs/gitlab.crt'` + "\n" +
				`nginx['ssl_certificate_key'] = '/secure/certs/gitlab.key'` + "\n",
			want: []api.InventoryItem{
				gitlabItem("gitlab", "/secure/certs/gitlab.crt", "/secure/certs/gitlab.key", "gitlab.example.com"),
			},
		},
		{
			name: "false tolerates missing and tab-separated assignment spacing",
			config: leOff + "external_url 'https://gitlab.example.com'\n" +
				"nginx['ssl_certificate']=\"/secure/nospace.crt\"\n" +
				"nginx['ssl_certificate_key']\t=\t\"/secure/tab.key\"\n",
			want: []api.InventoryItem{
				gitlabItem("gitlab", "/secure/nospace.crt", "/secure/tab.key", "gitlab.example.com"),
			},
		},
		{
			name: "false reports supported GitLab services as separate items",
			config: leOff + "external_url 'https://gitlab.example.com'\n" + explicitMainCert +
				"registry_external_url 'https://registry.example.com:5050'\n" +
				`registry_nginx['ssl_certificate'] = "/etc/gitlab/ssl/registry.example.com.crt"` + "\n" +
				`registry_nginx['ssl_certificate_key'] = "/etc/gitlab/ssl/registry.example.com.key"` + "\n" +
				"pages_external_url 'https://pages.example.com'\n" +
				`pages_nginx['ssl_certificate'] = "/etc/gitlab/ssl/pages.example.com.crt"` + "\n" +
				`pages_nginx['ssl_certificate_key'] = "/etc/gitlab/ssl/pages.example.com.key"` + "\n",
			want: []api.InventoryItem{
				gitlabItem("gitlab", "/etc/gitlab/ssl/host01.internal.example.com.crt", "/etc/gitlab/ssl/host01.internal.example.com.key", "gitlab.example.com"),
				gitlabItem("gitlab-registry", "/etc/gitlab/ssl/registry.example.com.crt", "/etc/gitlab/ssl/registry.example.com.key", "registry.example.com"),
				gitlabItem("gitlab-pages", "/etc/gitlab/ssl/pages.example.com.crt", "/etc/gitlab/ssl/pages.example.com.key", "pages.example.com"),
			},
		},
		{
			name: "false ignores commented cert lines and falls back to the machine FQDN",
			config: leOff + "external_url 'https://gitlab.example.com'\n" +
				`# nginx['ssl_certificate'] = "/etc/gitlab/ssl/#{node['fqdn']}.crt"` + "\n",
			want: []api.InventoryItem{
				gitlabItem("gitlab", "/etc/gitlab/ssl/host01.internal.example.com.crt", "/etc/gitlab/ssl/host01.internal.example.com.key", "gitlab.example.com"),
			},
		},

		// --- Edge cases (LE off, but nothing to report) -----------------------
		{
			name:   "http-only external_url yields no items",
			config: leOff + "external_url 'http://gitlab.example.com'\n",
			want:   nil,
		},
		{
			name:   "no external_url yields no items",
			config: leOff + "gitlab_rails['gitlab_shell_ssh_port'] = 22\n",
			want:   nil,
		},
		{
			name:   "malformed garbage yields no items",
			config: leOff + "this is not valid ruby\n\x00\x01 nginx[ ssl_certificate = \nexternal_url =\n}}}{{{",
			want:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseGitLabConfig([]byte(tt.config), gitlabConfigPath, testFQDN)
			assertInventoryItems(t, got, tt.want)
		})
	}
}

// TestGitLabCollectNeverErrors guards the "don't blow up the agent" contract:
// Collect must not return an error even when /etc/gitlab/gitlab.rb is absent
// (the usual case on a non-GitLab host).
func TestGitLabCollectNeverErrors(t *testing.T) {
	if _, err := (GitLabProvider{}).Collect(); err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
}

func TestNodeFQDN(t *testing.T) {
	// Host-dependent value, but it must be non-empty so the default cert path is
	// never /etc/gitlab/ssl/.crt.
	if nodeFQDN() == "" {
		t.Error("nodeFQDN() returned empty string")
	}
}

const explicitMainCert = `nginx['ssl_certificate'] = "/etc/gitlab/ssl/#{node['fqdn']}.crt"` + "\n" +
	`nginx['ssl_certificate_key'] = "/etc/gitlab/ssl/#{node['fqdn']}.key"` + "\n"

func gitlabItem(server, cert, key, domains string) api.InventoryItem {
	return api.InventoryItem{
		Server:          server,
		ConfigPath:      gitlabConfigPath,
		CertificatePath: cert,
		KeyPath:         key,
		Domains:         domains,
	}
}

func assertInventoryItems(t *testing.T, got, want []api.InventoryItem) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d items, want %d\n got: %+v\nwant: %+v", len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("item %d mismatch:\n got: %+v\nwant: %+v", i, got[i], want[i])
		}
	}
}
