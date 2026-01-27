#!/usr/bin/env bash
set -euo pipefail

cat /etc/haproxy/ssl/certkit.key /etc/haproxy/ssl/certkit.crt > /etc/haproxy/ssl/certkit.pem
haproxy -c -f /etc/haproxy/haproxy.cfg

if [[ -f /run/haproxy.pid ]]; then
  haproxy -f /etc/haproxy/haproxy.cfg -p /run/haproxy.pid -sf "$(cat /run/haproxy.pid)"
fi
