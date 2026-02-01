#!/usr/bin/env sh
set -euo pipefail

CONFIG_PATH="${CERTKIT_CONFIG_PATH:-/etc/certkit-agent/config.json}"
BIN_DIR="/opt/certkit-agent"
BIN_PATH="${BIN_DIR}/certkit-agent"
SOURCE="${CERTKIT_AGENT_SOURCE:-release}"

if [ "${SOURCE}" = "local" ]; then
  if [ -z "${CERTKIT_AGENT_BINARY:-}" ]; then
    echo "CERTKIT_AGENT_BINARY is required when CERTKIT_AGENT_SOURCE=local" >&2
    exit 1
  fi
  exec "${CERTKIT_AGENT_BINARY}" run --config "${CONFIG_PATH}"
fi

TAG="${CERTKIT_VERSION:-}"
if [ -z "${TAG}" ]; then
  TAG="$(curl -fsSLI -o /dev/null -w '%{url_effective}' \
    "https://github.com/certkit-io/certkit-agent/releases/latest" | sed -n 's#.*/tag/##p')"
  if [ -z "${TAG}" ]; then
    echo "Failed to determine latest release tag" >&2
    exit 1
  fi
fi

arch="$(uname -m)"
case "$arch" in
  x86_64|amd64)  arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  *)
    echo "Unsupported architecture: $arch" >&2
    exit 1
    ;;
esac

ASSET_BIN="certkit-agent_linux_${arch}"
ASSET_SHA="certkit-agent_SHA256SUMS.txt"
BASE_URL="https://github.com/certkit-io/certkit-agent/releases/download/${TAG}"

mkdir -p "${BIN_DIR}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "Downloading ${ASSET_BIN} (${TAG})"
curl -fsSL "${BASE_URL}/${ASSET_BIN}" -o "${tmp}/${ASSET_BIN}"
curl -fsSL "${BASE_URL}/${ASSET_SHA}" -o "${tmp}/${ASSET_SHA}"

(
  cd "$tmp"
  grep -E "^[a-f0-9]{64}[[:space:]]+${ASSET_BIN}\$" "${ASSET_SHA}" | sha256sum -c -
)

install -m 0755 "${tmp}/${ASSET_BIN}" "${BIN_PATH}"

exec "${BIN_PATH}" run --config "${CONFIG_PATH}"
