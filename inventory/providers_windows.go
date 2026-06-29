//go:build windows

package inventory

func getProviders() []Provider {
	return []Provider{
		IISProvider{},
		RemoteAccessProvider{},
		RDPProvider{},
		ExchangeProvider{},
		ApacheProvider{},
		FileZillaProvider{},
	}
}
