#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_BIN="$SCRIPT_DIR/certkit-agent"
chmod +x "$AGENT_BIN"

CONFIG_PATH="${CERTKIT_CONFIG_PATH:-/etc/certkit-agent/config.json}"
CRON_SCHEDULE="${CERTKIT_CRON_SCHEDULE:-* * * * *}"
CRON_LOG_PATH="${CERTKIT_CRON_LOG:-/var/log/certkit-agent/cron.log}"
KEY="${1:-${REGISTRATION_KEY:-}}"

if [[ -z "${KEY// }" ]]; then
  echo "registration key is required (pass as first argument or set REGISTRATION_KEY)" >&2
  exit 1
fi

mkdir -p "$(dirname "$CONFIG_PATH")"
mkdir -p "$(dirname "$CRON_LOG_PATH")"
touch "$CRON_LOG_PATH"

echo "Registering agent..."
"$AGENT_BIN" register "$KEY" --config "$CONFIG_PATH"

echo "Validating agent configuration..."
"$AGENT_BIN" validate --config "$CONFIG_PATH"

CRON_FILE="/etc/cron.d/certkit-agent"
cat > "$CRON_FILE" <<EOF
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

$CRON_SCHEDULE root for i in 1 2 3 4; do $AGENT_BIN run --once --config $CONFIG_PATH >> $CRON_LOG_PATH 2>&1; sleep 15; done
EOF

chmod 0644 "$CRON_FILE"

if pgrep -x cron >/dev/null 2>&1; then
  pkill -HUP cron || true
fi

echo "Cron schedule installed in $CRON_FILE"
echo "Schedule: $CRON_SCHEDULE"
echo "Log file: $CRON_LOG_PATH"
