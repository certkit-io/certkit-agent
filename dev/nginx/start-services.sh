#!/usr/bin/env bash
set -euo pipefail

nginx -t

/usr/local/bin/run-certkit-agent.sh &
agent_pid=$!

trap 'kill "$agent_pid"' EXIT

exec nginx -g "daemon off;"
