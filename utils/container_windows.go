//go:build windows

package utils

// IsContainerEnvironment returns false on Windows. Windows containers are not
// a supported deployment target for the certkit-agent.
func IsContainerEnvironment() bool {
	return false
}
