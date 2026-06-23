##! Sample GitLab Omnibus configuration used as a reference fixture for the
##! GitLab inventory provider. It exercises every service the provider reports:
##!   - gitlab            (main nginx, cert via #{node['fqdn']} interpolation)
##!   - gitlab-registry   (Container Registry, explicit literal cert)
##!   - gitlab-mattermost (Mattermost, explicit literal cert)
##!   - gitlab-pages      (GitLab Pages, explicit literal cert)
##!
##! letsencrypt['enable'] is false here so the bundled certs are treated as
##! locally managed rather than auto-renewed by GitLab. The commented-out lines
##! and unrelated settings below are intentional noise the parser must ignore.

external_url 'https://gitlab.example.com'

# Disable GitLab's built-in Let's Encrypt so the certs below are reported as
# certkit-manageable instead of being skipped as GitLab-managed.
letsencrypt['enable'] = false

# Main GitLab nginx vhost. The default template uses #{node['fqdn']} in the
# filename; the provider substitutes it with the external_url host.
nginx['ssl_certificate'] = "/etc/gitlab/ssl/#{node['fqdn']}.crt"
nginx['ssl_certificate_key'] = "/etc/gitlab/ssl/#{node['fqdn']}.key"

# Container Registry on its own subdomain/port.
registry_external_url 'https://registry.example.com:5050'
registry_nginx['ssl_certificate'] = "/etc/gitlab/ssl/registry.example.com.crt"
registry_nginx['ssl_certificate_key'] = "/etc/gitlab/ssl/registry.example.com.key"

# Bundled Mattermost.
mattermost_external_url 'https://mattermost.example.com'
mattermost_nginx['ssl_certificate'] = "/etc/gitlab/ssl/mattermost.example.com.crt"
mattermost_nginx['ssl_certificate_key'] = "/etc/gitlab/ssl/mattermost.example.com.key"

# GitLab Pages.
pages_external_url 'https://pages.example.com'
pages_nginx['ssl_certificate'] = "/etc/gitlab/ssl/pages.example.com.crt"
pages_nginx['ssl_certificate_key'] = "/etc/gitlab/ssl/pages.example.com.key"

# --- Unrelated settings the provider should ignore -------------------------
gitlab_rails['gitlab_shell_ssh_port'] = 22
gitlab_rails['time_zone'] = 'UTC'
# nginx['redirect_http_to_https'] = true
# nginx['listen_port'] = 443
prometheus_monitoring['enable'] = false
