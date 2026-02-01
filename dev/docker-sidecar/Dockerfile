FROM docker:25.0-cli

RUN apk add --no-cache bash curl ca-certificates coreutils

WORKDIR /opt/certkit-agent

COPY dev/docker-sidecar/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
