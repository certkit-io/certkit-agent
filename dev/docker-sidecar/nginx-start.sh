#!/usr/bin/env sh
set -euo pipefail

if [ ! -f /certs/nginx.crt ] || [ ! -f /certs/nginx.key ]; then
  echo "Generating self-signed cert for dev..."
  openssl req -x509 -nodes -newkey rsa:2048 -subj "/CN=localhost" \
    -keyout /certs/nginx.key -out /certs/nginx.crt -days 1
fi

if [ "${WATCH_CERTS:-}" = "1" ]; then
  if command -v inotifywait >/dev/null 2>&1; then
    echo "Watching /certs for changes and reloading nginx..."
    (
      while inotifywait -e close_write,create,delete,move /certs >/dev/null 2>&1; do
        nginx -s reload || true
      done
    ) &
  else
    echo "inotifywait not available; WATCH_CERTS ignored."
  fi
fi

exec nginx -g 'daemon off;'
