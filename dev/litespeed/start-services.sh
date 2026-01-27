#!/usr/bin/env bash
set -euo pipefail

/usr/local/lsws/bin/lswsctrl start

/usr/local/bin/run-certkit-agent.sh &
agent_pid=$!

trap 'kill "$agent_pid"' EXIT

tail -F /usr/local/lsws/logs/error.log
