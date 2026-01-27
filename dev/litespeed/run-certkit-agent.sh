#!/usr/bin/env bash
set -euo pipefail

cd /app

if [[ "${CERTKIT_AGENT_SOURCE:-local}" == "release" ]]; then
  curl -fsSL https://raw.githubusercontent.com/certkit-io/certkit-agent/main/scripts/install.sh | bash
  exec /usr/local/bin/certkit-agent run --config /app/dev/litespeed/config.json
fi

exec /usr/local/bin/certkit-agent run --config /app/dev/litespeed/config.json
