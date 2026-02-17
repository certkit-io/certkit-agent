package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/certkit-io/certkit-agent/config"
	"github.com/certkit-io/certkit-agent/utils"
)

type RegisterAgentRequest struct {
	PublicKey       string `json:"public_key"`
	Hostname        string `json:"hostname"`
	Version         string `json:"version"`
	RegistrationKey string `json:"registration_key"`
	MachineId       string `json:"machine_id"`
	OperatingSystem string `json:"operating_system"`
	Timezone        string `json:"timezone"`
	PathToBin       string `json:"path_to_bin"`
	PathToConfig    string `json:"path_to_config"`
	ServiceName     string `json:"service_name"`
	HostType        string `json:"host_type"`
}

type RegisterAgentResponse struct {
	AgentId string `json:"agent_id"`
}

func RegisterAgent() (*RegisterAgentResponse, error) {

	hostname, _ := os.Hostname()
	machineId, _ := utils.GetStableMachineID()
	pathToBin := ""
	if exePath, err := os.Executable(); err == nil {
		if resolved, resolveErr := filepath.EvalSymlinks(exePath); resolveErr == nil {
			pathToBin = resolved
		} else {
			pathToBin = exePath
		}
	}

	serviceName := "certkit-agent"
	if config.CurrentConfig.Bootstrap != nil {
		if value := strings.TrimSpace(config.CurrentConfig.Bootstrap.ServiceName); value != "" {
			serviceName = value
		}
	}
	zoneName, zoneOffsetSeconds := time.Now().Zone()

	payload := RegisterAgentRequest{
		PublicKey:       config.CurrentConfig.Auth.KeyPair.PublicKey,
		Hostname:        hostname,
		Version:         config.CurrentConfig.Version.Version,
		RegistrationKey: config.CurrentConfig.Bootstrap.RegistrationKey,
		MachineId:       machineId,
		OperatingSystem: runtime.GOOS,
		Timezone:        formatZoneWithOffset(zoneName, zoneOffsetSeconds),
		PathToBin:       pathToBin,
		PathToConfig:    config.CurrentPath,
		ServiceName:     serviceName,
		HostType:        detectHostType(),
	}

	// Marshal payload to JSON
	requestBody, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal json: %w", err)
	}

	// Build request with raw bytes
	req, err := http.NewRequest(
		http.MethodPost,
		config.CurrentConfig.ApiBase+"/api/agent/v1/register-agent",
		bytes.NewReader(requestBody),
	)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}

	// Required for JSON
	req.Header.Set("Content-Type", "application/json")

	// (Optional) Set a timeout at the client level
	client := &http.Client{
		Timeout: 15 * time.Second,
	}

	//privKey, _ := auth.DecodePrivateKey(config.CurrentConfig.Auth.KeyPair.PrivateKey)

	// err = auth.SignRequest(req, "Eric", privKey, time.Now())
	// if err != nil {
	// 	panic(err)
	// }

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http do: %w", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("install failed: status=%d body=%s", resp.StatusCode, body)
	}

	var installResp RegisterAgentResponse
	if err := json.Unmarshal(body, &installResp); err != nil {
		return nil, fmt.Errorf("decode register response: %w", err)
	}

	log.Printf("Successfully registered agent: %s", installResp.AgentId)

	return &installResp, nil
}

func detectHostType() string {
	if strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_HOST")) != "" {
		return "k8s"
	}
	if isDockerEnvironment() {
		return "docker"
	}
	if isVirtualMachineEnvironment() {
		return "VM"
	}
	return "Bare metal"
}

func isDockerEnvironment() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if runtime.GOOS != "linux" {
		return false
	}
	data, err := os.ReadFile("/proc/1/cgroup")
	if err != nil {
		return false
	}
	content := strings.ToLower(string(data))
	return strings.Contains(content, "docker") ||
		strings.Contains(content, "containerd") ||
		strings.Contains(content, "kubepods")
}

func isVirtualMachineEnvironment() bool {
	if runtime.GOOS == "windows" {
		return isVirtualMachineEnvironmentWindows()
	}

	if runtime.GOOS != "linux" {
		return false
	}

	if data, err := os.ReadFile("/sys/class/dmi/id/product_name"); err == nil {
		if looksVirtualized(string(data)) {
			return true
		}
	}
	if data, err := os.ReadFile("/sys/class/dmi/id/sys_vendor"); err == nil {
		if looksVirtualized(string(data)) {
			return true
		}
	}
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		if strings.Contains(strings.ToLower(string(data)), "hypervisor") {
			return true
		}
	}

	return false
}

func looksVirtualized(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return false
	}
	return strings.Contains(value, "vmware") ||
		strings.Contains(value, "virtualbox") ||
		strings.Contains(value, "kvm") ||
		strings.Contains(value, "qemu") ||
		strings.Contains(value, "microsoft corporation") ||
		strings.Contains(value, "hyper-v") ||
		strings.Contains(value, "xen")
}

func isVirtualMachineEnvironmentWindows() bool {
	// Prefer CIM data when available.
	out, err := exec.Command(
		"powershell",
		"-NoProfile",
		"-NonInteractive",
		"-Command",
		`$cs = Get-CimInstance Win32_ComputerSystem; "$($cs.Manufacturer)|$($cs.Model)|$($cs.HypervisorPresent)"`,
	).CombinedOutput()
	if err == nil {
		parsed := strings.ToLower(strings.TrimSpace(string(out)))
		if strings.Contains(parsed, "|true") {
			return true
		}
		if looksVirtualized(parsed) {
			return true
		}
	}

	// Fallback for hosts where CIM cmdlets are unavailable.
	out, err = exec.Command("wmic", "computersystem", "get", "manufacturer,model", "/value").CombinedOutput()
	if err == nil && looksVirtualized(string(out)) {
		return true
	}

	return false
}

func formatZoneWithOffset(zoneName string, offsetSeconds int) string {
	zoneName = strings.TrimSpace(zoneName)
	if zoneName == "" || strings.EqualFold(zoneName, "local") {
		zoneName = "UTC"
	}

	sign := "+"
	if offsetSeconds < 0 {
		sign = "-"
		offsetSeconds = -offsetSeconds
	}

	hours := offsetSeconds / 3600
	minutes := (offsetSeconds % 3600) / 60
	if minutes == 0 {
		return fmt.Sprintf("%s%s%d", zoneName, sign, hours)
	}
	return fmt.Sprintf("%s%s%d:%02d", zoneName, sign, hours, minutes)
}
