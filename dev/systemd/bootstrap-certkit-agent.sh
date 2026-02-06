#!/usr/bin/env bash
set -euo pipefail

export PATH="/usr/local/go/bin:$PATH"
export HOME="${HOME:-/root}"
export XDG_CACHE_HOME="${XDG_CACHE_HOME:-/tmp/.cache}"
export GOCACHE="${GOCACHE:-$XDG_CACHE_HOME/go-build}"
export GOPATH="${GOPATH:-/tmp/go}"

mkdir -p "$GOCACHE" "$GOPATH"

WORKDIR="${CERTKIT_WORKDIR:-/workspace}"
SOURCE_MODE="${CERTKIT_AGENT_SOURCE:-local}"
BUILD_OUTPUT="${CERTKIT_BUILD_OUTPUT:-/tmp/certkit-agent}"
INSTALL_BIN="${CERTKIT_INSTALL_BINARY:-/usr/local/bin/certkit-agent}"
CONFIG_PATH="${CERTKIT_CONFIG_PATH:-/workspace/dev/systemd/config.json}"
SERVICE_NAME="${CERTKIT_SERVICE_NAME:-certkit-agent}"

if [[ "$SOURCE_MODE" == "release" ]]; then
  echo "Installing release build via install.sh"
  curl -fsSL https://raw.githubusercontent.com/certkit-io/certkit-agent/main/scripts/install.sh | bash
else
  if ! command -v go >/dev/null 2>&1; then
    echo "go toolchain not found in PATH: $PATH" >&2
    exit 1
  fi

  echo "Building certkit-agent from source at $WORKDIR"
  cd "$WORKDIR"
  go build -ldflags "-X main.version=v1.2.3" -o "$BUILD_OUTPUT" ./cmd/certkit-agent
  echo "Installing built binary to $INSTALL_BIN"
  install -m 0755 "$BUILD_OUTPUT" "$INSTALL_BIN"
fi

echo "Installing/updating systemd service: $SERVICE_NAME"
"$INSTALL_BIN" install \
  --service-name "$SERVICE_NAME" \
  --unit-dir /etc/systemd/system \
  --bin-path "$INSTALL_BIN" \
  --config "$CONFIG_PATH"

echo "certkit-agent bootstrap complete"
