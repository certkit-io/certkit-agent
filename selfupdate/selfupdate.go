package selfupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/certkit-io/certkit-agent/utils"
)

// pendingUpdate holds the in-memory update signal from the server.
// Set by SignalUpdateAvailable, consumed by HandleUpdateIfNeeded.
var pendingUpdate *updateSignal

type updateSignal struct {
	Version     string
	DownloadURL string
	SHA256      string
}

// SignalUpdateAvailable stores an update signal in memory. Called from
// PollForConfiguration when the server includes update_available in the response.
func SignalUpdateAvailable(currentVersion, version, downloadURL, sha256hex string) {
	version = strings.TrimSpace(version)
	if version == "" || downloadURL == "" || sha256hex == "" {
		return
	}
	if version == currentVersion {
		return
	}
	if pendingUpdate != nil && pendingUpdate.Version == version {
		return
	}

	pendingUpdate = &updateSignal{
		Version:     version,
		DownloadURL: downloadURL,
		SHA256:      sha256hex,
	}
	log.Printf("Self-update: version %s available, queued for update", version)
}

// HandleUpdateIfNeeded checks for a pending update signal and, if present,
// downloads, verifies, and replaces the binary. Returns true if the caller
// should trigger a restart.
func HandleUpdateIfNeeded(configPath string) bool {
	if pendingUpdate == nil {
		return false
	}
	signal := pendingUpdate
	pendingUpdate = nil

	if utils.IsContainerEnvironment() {
		log.Printf("Running in container, skipping self-update to %s", signal.Version)
		return false
	}

	log.Printf("Self-update: downloading version %s", signal.Version)

	exe, err := resolveExecutablePath()
	if err != nil {
		log.Printf("Self-update: %v", err)
		return false
	}

	ext := filepath.Ext(exe)
	stagingPath := filepath.Join(filepath.Dir(exe), "certkit-agent.new"+ext)

	if err := downloadAndVerify(signal.DownloadURL, signal.SHA256, stagingPath); err != nil {
		log.Printf("Self-update: download failed: %v", err)
		os.Remove(stagingPath)
		return false
	}

	log.Printf("Self-update: download verified, replacing binary")

	if err := replaceBinary(stagingPath); err != nil {
		log.Printf("Self-update: binary replacement failed: %v", err)
		os.Remove(stagingPath)
		return false
	}

	log.Printf("Self-update: binary replaced, restart required")
	return true
}

// --- Download ---

func downloadAndVerify(url, expectedSHA256, destPath string) error {
	expectedSHA256 = strings.ToLower(strings.TrimSpace(expectedSHA256))
	if expectedSHA256 == "" {
		return fmt.Errorf("expected SHA256 checksum is empty")
	}

	dir := filepath.Dir(destPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create download directory: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".certkit-update-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		tmp.Close()
		os.Remove(tmpPath)
	}

	client := &http.Client{Timeout: 5 * time.Minute}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		cleanup()
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", "certkit-agent")

	resp, err := client.Do(req)
	if err != nil {
		cleanup()
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		cleanup()
		return fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}

	hasher := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, hasher), resp.Body); err != nil {
		cleanup()
		return fmt.Errorf("write download: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("close temp file: %w", err)
	}

	actual := hex.EncodeToString(hasher.Sum(nil))
	if actual != expectedSHA256 {
		os.Remove(tmpPath)
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedSHA256, actual)
	}

	if err := os.Rename(tmpPath, destPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("move download to destination: %w", err)
	}
	return nil
}

// --- Helpers ---

func resolveExecutablePath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("determine executable path: %w", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return "", fmt.Errorf("resolve symlinks: %w", err)
	}
	return exe, nil
}
