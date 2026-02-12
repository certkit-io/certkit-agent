FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    cron \
    curl \
    procps \
  && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/certkit-agent /etc/certkit-agent /var/log/certkit-agent

COPY dist/bin/certkit-agent_linux_amd64 /opt/certkit-agent/certkit-agent
COPY dev/cron/setup-cron.sh /opt/certkit-agent/setup-cron.sh
COPY dev/cron/start-services.sh /usr/local/bin/start-services.sh

RUN chmod +x /opt/certkit-agent/certkit-agent \
  && chmod +x /opt/certkit-agent/setup-cron.sh \
  && chmod +x /usr/local/bin/start-services.sh

WORKDIR /opt/certkit-agent

CMD ["/usr/local/bin/start-services.sh"]
