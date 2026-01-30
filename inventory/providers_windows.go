//go:build windows

package inventory

func getProviders() []Provider {
	return []Provider{
		IISProvider{},
	}
}
