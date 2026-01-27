#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

APP_NAME="certkit-agent"
MAIN_PKG="./cmd/certkit-agent"   # <-- change if needed
DIST_DIR="${DIST_DIR:-dist}"

# Versioning: prefer git tag, fall back to short sha
VERSION="${VERSION:-$(git describe --tags --always --dirty)}"
COMMIT="${COMMIT:-$(git rev-parse --short HEAD)}"
BUILD_DATE="${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"

mkdir -p "$DIST_DIR"
rm -rf "$DIST_DIR"/*
mkdir -p "$DIST_DIR/bin"

LDFLAGS="-s -w \
  -X main.version=$VERSION \
  -X main.commit=$COMMIT \
  -X main.date=$BUILD_DATE"

build_one () {
  local goos="$1"
  local goarch="$2"
  local ext="$3"

  local out="${DIST_DIR}/bin/${APP_NAME}_${goos}_${goarch}${ext}"

  echo "==> Building $goos/$goarch -> $out"
  env CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath -ldflags "$LDFLAGS" -o "$out" "$MAIN_PKG"
}

# Adjust architectures as you like
build_one linux amd64 ""
build_one linux arm64 ""
build_one windows amd64 ".exe"

echo "==> Checksums"
(
  cd "$DIST_DIR/bin"
  sha256sum * > "../${APP_NAME}_SHA256SUMS.txt"
)

echo "==> Done. Outputs in: $DIST_DIR"
ls -lah "$DIST_DIR/bin"
ls -lah "$DIST_DIR"/*.txt
