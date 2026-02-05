#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root (sudo ...)" >&2
  exit 1
fi

OWNER="certkit-io"
REPO="certkit-agent"

BIN_NAME="certkit-agent"
INSTALL_DIR="/usr/local/bin"

FIRST_INSTALL=0
if [[ ! -f "${INSTALL_DIR}/${BIN_NAME}" ]]; then
  FIRST_INSTALL=1
fi

# Resolve release tag (latest unless VERSION set)
if [[ -n "${VERSION:-}" ]]; then
  TAG="$VERSION"
else
  TAG="$(curl -fsSLI -o /dev/null -w '%{url_effective}' \
    "https://github.com/${OWNER}/${REPO}/releases/latest" | sed -n 's#.*/tag/##p')"
  if [[ -z "$TAG" ]]; then
    echo "Failed to determine latest release tag" >&2
    exit 1
  fi
fi

echo "Using release tag: ${TAG}"

# Detect architecture
arch="$(uname -m)"
case "$arch" in
  x86_64|amd64)  arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  *)
    echo "Unsupported architecture: $arch" >&2
    exit 1
    ;;
esac

ASSET_BIN="${BIN_NAME}_linux_${arch}"
ASSET_SHA="${BIN_NAME}_SHA256SUMS.txt"
BASE_URL="https://github.com/${OWNER}/${REPO}/releases/download/${TAG}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "Downloading ${ASSET_BIN}"
curl -fsSL "${BASE_URL}/${ASSET_BIN}" -o "$tmp/${ASSET_BIN}"

echo "Downloading ${ASSET_SHA}"
curl -fsSL "${BASE_URL}/${ASSET_SHA}" -o "$tmp/${ASSET_SHA}"

echo "Verifying checksum"
(
  cd "$tmp"
  grep -E "^[a-f0-9]{64}[[:space:]]+${ASSET_BIN}\$" "${ASSET_SHA}" | sha256sum -c -
)

echo "Installing binary to ${INSTALL_DIR}/${BIN_NAME}"
install -m 0755 "$tmp/${ASSET_BIN}" "${INSTALL_DIR}/${BIN_NAME}"

echo "Running certkit-agent install..."
echo "Installation output:"
/usr/local/bin/${BIN_NAME} install

if [[ $FIRST_INSTALL -eq 0 ]]; then
  if command -v systemctl >/dev/null 2>&1; then
    echo "Restarting certkit-agent.service"
    systemctl restart certkit-agent.service
  else
    echo "Skipping systemd restart (systemctl not available)"
  fi
fi

echo "Installation complete."
if [[ -n "${REGISTRATION_KEY:-}" ]]; then
  app_id="${REGISTRATION_KEY%%.*}"
  echo "Finish configuring this agent: https://app.certkit.io/app/${app_id}/agents/"
else
  echo "Finish configuring this agent in the CertKit UI: https://app.certkit.io"
fi
