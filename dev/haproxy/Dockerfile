FROM golang:1.24

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    curl \
    haproxy \
    openssl \
  && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/haproxy/ssl
RUN openssl req -x509 -nodes -newkey rsa:2048 \
  -subj "/CN=localhost" \
  -keyout /etc/haproxy/ssl/certkit.key \
  -out /etc/haproxy/ssl/certkit.crt \
  -days 1
RUN cat /etc/haproxy/ssl/certkit.key /etc/haproxy/ssl/certkit.crt > /etc/haproxy/ssl/certkit.pem

COPY dev/haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg
COPY dev/haproxy/run-certkit-agent.sh /usr/local/bin/run-certkit-agent.sh
COPY dev/haproxy/start-services.sh /usr/local/bin/start-services.sh
COPY dev/haproxy/reload-haproxy.sh /usr/local/bin/reload-haproxy.sh

RUN chmod +x /usr/local/bin/run-certkit-agent.sh \
  && chmod +x /usr/local/bin/start-services.sh \
  && chmod +x /usr/local/bin/reload-haproxy.sh

EXPOSE 443

CMD ["/usr/local/bin/start-services.sh"]
