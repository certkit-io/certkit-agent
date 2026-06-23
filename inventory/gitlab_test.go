package inventory

import (
	"os"
	"testing"

	"github.com/certkit-io/certkit-agent/api"
)

const (
	gitlabConfigPath = "/etc/gitlab/gitlab.rb"
	testFQDN         = "host01.internal.example.com"
)

func TestParseGitLabConfig(t *testing.T) {
	tests := []struct {
		name   string
		config string
		want   []api.InventoryItem
	}{
		{
			name:   "stock default lets encrypt auto-enabled is skipped",
			config: "external_url 'https://gitlab.example.com'\n",
			want:   nil,
		},
		{
			name: "lets encrypt disabled falls back to the MACHINE FQDN path",
			config: "external_url 'https://gitlab.example.com'\n" +
				"letsencrypt['enable'] = false\n",
			want: []api.InventoryItem{
				{
					Server:          "gitlab",
					ConfigPath:      gitlabConfigPath,
					CertificatePath: "/etc/gitlab/ssl/host01.internal.example.com.crt",
					KeyPath:         "/etc/gitlab/ssl/host01.internal.example.com.key",
					Domains:         "gitlab.example.com",
				},
			},
		},
		{
			name: "explicit cert with node fqdn interpolation uses the machine FQDN",
			config: "external_url 'https://gitlab.example.com'\n" +
				`nginx['ssl_certificate'] = "/etc/gitlab/ssl/#{node['fqdn']}.crt"` + "\n" +
				`nginx['ssl_certificate_key'] = "/etc/gitlab/ssl/#{node['fqdn']}.key"` + "\n",
			want: []api.InventoryItem{
				{
					Server:          "gitlab",
					ConfigPath:      gitlabConfigPath,
					CertificatePath: "/etc/gitlab/ssl/host01.internal.example.com.crt",
					KeyPath:         "/etc/gitlab/ssl/host01.internal.example.com.key",
					Domains:         "gitlab.example.com",
				},
			},
		},
		{
			name: "explicit literal paths with single quotes",
			config: `external_url "https://gitlab.example.com"` + "\n" +
				`nginx['ssl_certificate'] = '/secure/certs/gitlab.crt'` + "\n" +
				`nginx['ssl_certificate_key'] = '/secure/certs/gitlab.key'` + "\n",
			want: []api.InventoryItem{
				{
					Server:          "gitlab",
					ConfigPath:      gitlabConfigPath,
					CertificatePath: "/secure/certs/gitlab.crt",
					KeyPath:         "/secure/certs/gitlab.key",
					Domains:         "gitlab.example.com",
				},
			},
		},
		{
			name: "tolerates missing and tab-separated assignment spacing",
			config: "external_url 'https://gitlab.example.com'\n" +
				"nginx['ssl_certificate']=\"/secure/nospace.crt\"\n" +
				"nginx['ssl_certificate_key']\t=\t\"/secure/tab.key\"\n",
			want: []api.InventoryItem{
				{
					Server:          "gitlab",
					ConfigPath:      gitlabConfigPath,
					CertificatePath: "/secure/nospace.crt",
					KeyPath:         "/secure/tab.key",
					Domains:         "gitlab.example.com",
				},
			},
		},
		{
			name: "registry and mattermost become separate items",
			config: "external_url 'https://gitlab.example.com'\n" +
				`nginx['ssl_certificate'] = "/etc/gitlab/ssl/gitlab.example.com.crt"` + "\n" +
				`nginx['ssl_certificate_key'] = "/etc/gitlab/ssl/gitlab.example.com.key"` + "\n" +
				"registry_external_url 'https://registry.example.com:5050'\n" +
				`registry_nginx['ssl_certificate'] = "/etc/gitlab/ssl/registry.example.com.crt"` + "\n" +
				`registry_nginx['ssl_certificate_key'] = "/etc/gitlab/ssl/registry.example.com.key"` + "\n" +
				"mattermost_external_url 'https://mattermost.example.com'\n" +
				`mattermost_nginx['ssl_certificate'] = "/etc/gitlab/ssl/mattermost.example.com.crt"` + "\n" +
				`mattermost_nginx['ssl_certificate_key'] = "/etc/gitlab/ssl/mattermost.example.com.key"` + "\n",
			want: []api.InventoryItem{
				{
					Server:          "gitlab",
					ConfigPath:      gitlabConfigPath,
					CertificatePath: "/etc/gitlab/ssl/gitlab.example.com.crt",
					KeyPath:         "/etc/gitlab/ssl/gitlab.example.com.key",
					Domains:         "gitlab.example.com",
				},
				{
					Server:          "gitlab-registry",
					ConfigPath:      gitlabConfigPath,
					CertificatePath: "/etc/gitlab/ssl/registry.example.com.crt",
					KeyPath:         "/etc/gitlab/ssl/registry.example.com.key",
					Domains:         "registry.example.com",
				},
				{
					Server:          "gitlab-mattermost",
					ConfigPath:      gitlabConfigPath,
					CertificatePath: "/etc/gitlab/ssl/mattermost.example.com.crt",
					KeyPath:         "/etc/gitlab/ssl/mattermost.example.com.key",
					Domains:         "mattermost.example.com",
				},
			},
		},
		{
			name: "lets-encrypt-managed registry is skipped while explicit main is kept",
			config: "external_url 'https://gitlab.example.com'\n" +
				`nginx['ssl_certificate'] = "/etc/gitlab/ssl/gitlab.example.com.crt"` + "\n" +
				`nginx['ssl_certificate_key'] = "/etc/gitlab/ssl/gitlab.example.com.key"` + "\n" +
				"registry_external_url 'https://registry.example.com'\n",
			want: []api.InventoryItem{
				{
					Server:          "gitlab",
					ConfigPath:      gitlabConfigPath,
					CertificatePath: "/etc/gitlab/ssl/gitlab.example.com.crt",
					KeyPath:         "/etc/gitlab/ssl/gitlab.example.com.key",
					Domains:         "gitlab.example.com",
				},
			},
		},
		{
			name:   "http-only external_url yields no items",
			config: "external_url 'http://gitlab.example.com'\n",
			want:   nil,
		},
		{
			name:   "no external_url yields no items",
			config: "gitlab_rails['gitlab_shell_ssh_port'] = 22\n",
			want:   nil,
		},
		{
			name: "commented cert lines are ignored and fall back to the machine FQDN",
			config: "external_url 'https://gitlab.example.com'\n" +
				`# nginx['ssl_certificate'] = "/etc/gitlab/ssl/#{node['fqdn']}.crt"` + "\n" +
				"letsencrypt['enable'] = false\n",
			want: []api.InventoryItem{
				{
					Server:          "gitlab",
					ConfigPath:      gitlabConfigPath,
					CertificatePath: "/etc/gitlab/ssl/host01.internal.example.com.crt",
					KeyPath:         "/etc/gitlab/ssl/host01.internal.example.com.key",
					Domains:         "gitlab.example.com",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseGitLabConfig([]byte(tt.config), gitlabConfigPath, testFQDN)
			assertInventoryItems(t, got, tt.want)
		})
	}
}

// TestParseGitLabSampleConfig runs the gitlab.test.rb sample through the parser,
// exercising all four services end-to-end.
func TestParseGitLabSampleConfig(t *testing.T) {
	data, err := os.ReadFile("gitlab.test.rb")
	if err != nil {
		t.Fatal(err)
	}

	got := parseGitLabConfig(data, gitlabConfigPath, testFQDN)
	want := []api.InventoryItem{
		{
			Server:          "gitlab",
			ConfigPath:      gitlabConfigPath,
			CertificatePath: "/etc/gitlab/ssl/host01.internal.example.com.crt",
			KeyPath:         "/etc/gitlab/ssl/host01.internal.example.com.key",
			Domains:         "gitlab.example.com",
		},
		{
			Server:          "gitlab-registry",
			ConfigPath:      gitlabConfigPath,
			CertificatePath: "/etc/gitlab/ssl/registry.example.com.crt",
			KeyPath:         "/etc/gitlab/ssl/registry.example.com.key",
			Domains:         "registry.example.com",
		},
		{
			Server:          "gitlab-mattermost",
			ConfigPath:      gitlabConfigPath,
			CertificatePath: "/etc/gitlab/ssl/mattermost.example.com.crt",
			KeyPath:         "/etc/gitlab/ssl/mattermost.example.com.key",
			Domains:         "mattermost.example.com",
		},
		{
			Server:          "gitlab-pages",
			ConfigPath:      gitlabConfigPath,
			CertificatePath: "/etc/gitlab/ssl/pages.example.com.crt",
			KeyPath:         "/etc/gitlab/ssl/pages.example.com.key",
			Domains:         "pages.example.com",
		},
	}
	assertInventoryItems(t, got, want)
}

func TestNodeFQDN(t *testing.T) {
	// Host-dependent value, but it must be non-empty so the default cert path is
	// never /etc/gitlab/ssl/.crt.
	if nodeFQDN() == "" {
		t.Error("nodeFQDN() returned empty string")
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
