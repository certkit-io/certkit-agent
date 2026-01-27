package inventory

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/certkit-io/certkit-agent-alpha/api"
	"github.com/certkit-io/certkit-agent-alpha/utils"
)

type Provider interface {
	Name() string
	Collect() ([]api.InventoryItem, error)
}

func Collect() ([]api.InventoryItem, error) {
	providers := []Provider{
		NginxProvider{},
		ApacheProvider{},
		LitespeedProvider{},
		HaproxyProvider{},
	}

	items := make([]api.InventoryItem, 0)
	for _, provider := range providers {
		providerItems, err := provider.Collect()
		if err != nil {
			return nil, fmt.Errorf("%s inventory: %w", provider.Name(), err)
		}
		items = append(items, providerItems...)
	}

	return items, nil
}

func expandConfigGlobs(globs []string) ([]string, error) {
	seen := make(map[string]struct{})
	for _, pattern := range globs {
		if !strings.ContainsAny(pattern, "*?[") {
			exists, err := utils.FileExists(pattern)
			if err != nil {
				return nil, err
			}
			if exists {
				seen[pattern] = struct{}{}
			}
			continue
		}
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return nil, err
		}
		for _, match := range matches {
			seen[match] = struct{}{}
		}
	}

	paths := make([]string, 0, len(seen))
	for path := range seen {
		paths = append(paths, path)
	}
	return paths, nil
}

func cleanConfigValue(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"'`)
	return value
}
