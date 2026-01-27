#!/usr/bin/env bash
set -euo pipefail

haproxy -c -f /etc/haproxy/haproxy.cfg

/usr/local/bin/run-certkit-agent.sh &
agent_pid=$!

trap 'kill "$agent_pid"' EXIT

exec haproxy -W -f /etc/haproxy/haproxy.cfg -p /run/haproxy.pid -db
