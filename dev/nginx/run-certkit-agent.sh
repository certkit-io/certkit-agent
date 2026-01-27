#!/usr/bin/env bash
set -euo pipefail

cd /app

if [[ "${CERTKIT_AGENT_SOURCE:-local}" == "release" ]]; then
  curl -fsSL https://raw.githubusercontent.com/certkit-io/certkit-agent/main/scripts/install.sh | bash
  exec /usr/local/bin/certkit-agent run --config /app/dev/nginx/config.json
fi

go build -ldflags "-X main.version=v1.2.3" -o ./dist/certkit-agent ./cmd/certkit-agent
exec ./dist/certkit-agent run --config /app/dev/nginx/config.json
