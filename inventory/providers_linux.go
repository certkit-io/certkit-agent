//go:build linux

package inventory

func getProviders() []Provider {
	return []Provider{
		NginxProvider{},
		ApacheProvider{},
		LitespeedProvider{},
		HaproxyProvider{},
	}
}
