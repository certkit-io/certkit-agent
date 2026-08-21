#!/usr/bin/env bash
# Builds the "legacy" Windows agent for Windows Server 2008 R2 / 2012 R2 (and Win 7 / 8.1).
# See legacy/README.md and legacy/build.ps1 for the full story.
#
# One-time setup:
#   go install golang.org/dl/go1.20.14@latest && go1.20.14 download
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

LEGACY_GO="${LEGACY_GO:-go1.20.14}"
DIST_DIR="${DIST_DIR:-dist}"
OUT="${OUT:-$DIST_DIR/bin/certkit-agent_windows_amd64_legacy.exe}"
MOD_FILE="legacy/go.legacy.mod"

if ! command -v "$LEGACY_GO" >/dev/null 2>&1; then
  if [ -x "$HOME/go/bin/$LEGACY_GO" ]; then
    LEGACY_GO="$HOME/go/bin/$LEGACY_GO"
  else
    echo "error: $LEGACY_GO not found. Install with: go install golang.org/dl/$LEGACY_GO@latest && $LEGACY_GO download" >&2
    exit 1
  fi
fi

GO_VERSION="$("$LEGACY_GO" version)"
case "$GO_VERSION" in
  *go1.20.*) ;;
  *) echo "error: expected a Go 1.20.x toolchain for the legacy build, got: $GO_VERSION" >&2; exit 1 ;;
esac
echo "==> Using legacy toolchain: $GO_VERSION"

VERSION="${VERSION:-$(git describe --tags --always --dirty)}"
case "$VERSION" in
  *+legacy) ;;
  *) VERSION="${VERSION}+legacy" ;;   # build metadata: identifies the variant, ignored by semver ordering
esac
COMMIT="${COMMIT:-$(git rev-parse --short HEAD)}"
BUILD_DATE="${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"

LDFLAGS="-s -w \
  -X main.version=$VERSION \
  -X main.commit=$COMMIT \
  -X main.date=$BUILD_DATE"

mkdir -p "$(dirname "$OUT")"
echo "==> Building legacy windows/amd64 ($VERSION) -> $OUT"
env CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
  "$LEGACY_GO" build -modfile "$MOD_FILE" -trimpath -ldflags "$LDFLAGS" -o "$OUT" ./cmd/certkit-agent

echo "==> Built: $("$LEGACY_GO" version "$OUT")"
