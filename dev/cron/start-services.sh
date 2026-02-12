#!/usr/bin/env bash
set -euo pipefail

mkdir -p /var/log/certkit-agent
touch /var/log/certkit-agent/cron.log
chmod +x /opt/certkit-agent/certkit-agent

cron

echo "cron started"
echo "Use /opt/certkit-agent/setup-cron.sh to register/validate and install cron job"

exec tail -F /var/log/certkit-agent/cron.log
