package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/certkit-io/certkit-agent/agent"
	"github.com/certkit-io/certkit-agent/config"
)

func doRegister(configPath string, key string) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return fmt.Errorf("--key is required")
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		if err := config.CreateInitialConfig(configPath, key, ""); err != nil {
			return err
		}
	}

	if _, err := config.LoadConfig(configPath, Version()); err != nil {
		return err
	}

	if config.CurrentConfig.Bootstrap == nil {
		config.CurrentConfig.Bootstrap = &config.BootstrapCreds{}
	}
	config.CurrentConfig.Bootstrap.RegistrationKey = key
	if err := config.SaveConfig(&config.CurrentConfig, config.CurrentPath); err != nil {
		return fmt.Errorf("save config with registration key: %w", err)
	}

	if !agent.NeedsRegistration() {
		log.Printf("Agent already registered: %s", config.CurrentConfig.Agent.AgentId)
		return nil
	}

	agent.DoRegistration()
	if agent.NeedsRegistration() {
		return fmt.Errorf("agent registration did not complete")
	}

	return nil
}

func doValidate(configPath string) error {
	cfg, err := config.ReadConfigFile(configPath)
	if err != nil {
		return err
	}

	apiBase := strings.TrimSpace(cfg.ApiBase)
	registrationKey := ""
	serviceName := defaultServiceName
	if cfg.Bootstrap != nil {
		registrationKey = strings.TrimSpace(cfg.Bootstrap.RegistrationKey)
		if s := strings.TrimSpace(cfg.Bootstrap.ServiceName); s != "" {
			serviceName = s
		}
	}

	agentID := ""
	if cfg.Agent != nil {
		agentID = strings.TrimSpace(cfg.Agent.AgentId)
	}

	configCount := len(cfg.CertificateConfigurations)
	hasAgent := agentID != ""
	hasBootstrap := registrationKey != ""

	hasKeyPair := false
	keyPairValid := false
	if cfg.Auth != nil && cfg.Auth.KeyPair != nil {
		hasPublic := strings.TrimSpace(cfg.Auth.KeyPair.PublicKey) != ""
		hasPrivate := strings.TrimSpace(cfg.Auth.KeyPair.PrivateKey) != ""
		hasKeyPair = hasPublic && hasPrivate
		if hasKeyPair {
			if _, err := cfg.Auth.KeyPair.DecodePrivateKey(); err == nil {
				keyPairValid = true
			}
		}
	}

	networkStatus, networkReachable := checkAPIReachability(apiBase)
	serviceStatus := detectServiceStatus(serviceName)

	log.Printf("Validation report:")
	log.Printf("  api base: %s", valueOr(apiBase, "(missing)"))
	log.Printf("  registration key: %s", valueOr(registrationKey, "(missing)"))
	log.Printf("  agent id: %s", valueOr(agentID, "(not registered)"))
	log.Printf("  certificate config count: %d", configCount)
	log.Printf("  network reachability: %s", networkStatus)
	log.Printf("  signing keypair generated: %t", hasKeyPair)
	log.Printf("  signing keypair valid: %t", keyPairValid)
	log.Printf("  registered: %t", hasAgent)
	log.Printf("  service configured in config: %s", valueOr(serviceName, "(missing)"))
	log.Printf("  service status: %s", serviceStatus)

	problems := make([]string, 0, 6)
	if apiBase == "" {
		problems = append(problems, "config missing api_base")
	} else if _, err := url.ParseRequestURI(apiBase); err != nil {
		problems = append(problems, fmt.Sprintf("invalid api_base %q", apiBase))
	}
	if !hasAgent && !hasBootstrap {
		problems = append(problems, "missing both registration key and agent id")
	}
	if !hasKeyPair {
		problems = append(problems, "signing keypair is missing")
	} else if !keyPairValid {
		problems = append(problems, "signing keypair is invalid")
	}
	if !networkReachable {
		problems = append(problems, "api base is not reachable over the network")
	}

	if len(problems) > 0 {
		return fmt.Errorf("validation failed: %s", strings.Join(problems, "; "))
	}

	log.Printf("Validation successful for %s", configPath)
	return nil
}

func checkAPIReachability(apiBase string) (string, bool) {
	apiBase = strings.TrimSpace(apiBase)
	if apiBase == "" {
		return "unreachable (api_base missing)", false
	}

	parsedURL, err := url.ParseRequestURI(apiBase)
	if err != nil {
		return fmt.Sprintf("unreachable (invalid api_base: %v)", err), false
	}

	port := parsedURL.Port()
	if port == "" {
		if strings.EqualFold(parsedURL.Scheme, "https") {
			port = "443"
		} else {
			port = "80"
		}
	}
	address := net.JoinHostPort(parsedURL.Hostname(), port)

	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return fmt.Sprintf("unreachable (tcp %s failed: %v)", address, err), false
	}
	_ = conn.Close()

	req, err := http.NewRequest(http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return fmt.Sprintf("reachable (tcp %s), HTTP check skipped: %v", address, err), true
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Sprintf("reachable (tcp %s), HTTP request failed: %v", address, err), true
	}
	_ = resp.Body.Close()

	return fmt.Sprintf("reachable (tcp %s, http status %d)", address, resp.StatusCode), true
}

func detectServiceStatus(serviceName string) string {
	serviceName = strings.TrimSpace(serviceName)
	if serviceName == "" {
		serviceName = defaultServiceName
	}

	switch runtime.GOOS {
	case "windows":
		out, err := exec.Command("sc.exe", "query", serviceName).CombinedOutput()
		text := strings.TrimSpace(string(out))
		lower := strings.ToLower(text)
		if err != nil {
			if strings.Contains(lower, "1060") || strings.Contains(lower, "does not exist") {
				return fmt.Sprintf("not installed (service %s)", serviceName)
			}
			return fmt.Sprintf("unknown (query error: %v)", err)
		}

		state := "state unknown"
		for _, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "STATE") {
				state = line
				break
			}
		}
		return fmt.Sprintf("installed (%s)", state)

	case "linux":
		if _, err := exec.LookPath("systemctl"); err != nil {
			return "unknown (systemctl not found)"
		}

		unitName := serviceName + ".service"
		out, err := exec.Command("systemctl", "show", unitName, "-p", "LoadState", "-p", "ActiveState", "--value").CombinedOutput()
		text := strings.TrimSpace(string(out))
		if err != nil {
			lower := strings.ToLower(text + " " + err.Error())
			if strings.Contains(lower, "not-found") || strings.Contains(lower, "could not be found") {
				return fmt.Sprintf("not installed (unit %s)", unitName)
			}
			return fmt.Sprintf("unknown (systemctl error: %v)", err)
		}

		lines := strings.Split(text, "\n")
		loadState := "unknown"
		activeState := "unknown"
		if len(lines) > 0 && strings.TrimSpace(lines[0]) != "" {
			loadState = strings.TrimSpace(lines[0])
		}
		if len(lines) > 1 && strings.TrimSpace(lines[1]) != "" {
			activeState = strings.TrimSpace(lines[1])
		}
		if strings.EqualFold(loadState, "not-found") {
			return fmt.Sprintf("not installed (unit %s)", unitName)
		}
		return fmt.Sprintf("installed (unit %s, load=%s, active=%s)", unitName, loadState, activeState)
	}

	return fmt.Sprintf("unknown (service check not implemented for %s)", runtime.GOOS)
}

func valueOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func versionCmd() {
	fmt.Printf("certkit-agent %s\n", version)
	fmt.Printf("commit: %s\n", commit)
	fmt.Printf("built: %s\n", date)
	fmt.Printf("go: %s\n", runtime.Version())
	fmt.Printf("os/arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
}
