#!/usr/bin/env bash
set -euo pipefail

apachectl -t

/usr/local/bin/run-certkit-agent.sh &
agent_pid=$!

trap 'kill "$agent_pid"' EXIT

exec apachectl -DFOREGROUND
