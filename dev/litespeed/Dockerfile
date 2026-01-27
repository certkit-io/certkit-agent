FROM golang:1.24 AS builder

WORKDIR /src
COPY . .
RUN go build -ldflags "-X main.version=v1.2.3" -o /out/certkit-agent ./cmd/certkit-agent

FROM litespeedtech/openlitespeed:latest

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    curl \
  && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /usr/local/lsws/conf/ssl
RUN openssl req -x509 -nodes -newkey rsa:2048 \
  -subj "/CN=localhost" \
  -keyout /usr/local/lsws/conf/ssl/certkit.key \
  -out /usr/local/lsws/conf/ssl/certkit.crt \
  -days 1
RUN cat <<'EOF' >> /usr/local/lsws/conf/httpd_config.conf
listener SSL_8443 {
  address                 *:8443
  secure                  1
  keyFile                 /usr/local/lsws/conf/ssl/certkit.key
  certFile                /usr/local/lsws/conf/ssl/certkit.crt
  sslCertFile             /usr/local/lsws/conf/ssl/certkit.crt
  sslKeyFile              /usr/local/lsws/conf/ssl/certkit.key
  map                     Example *
}
EOF


COPY dev/litespeed/vhconf.conf /usr/local/lsws/conf/vhosts/Example/vhconf.conf
COPY dev/litespeed/run-certkit-agent.sh /usr/local/bin/run-certkit-agent.sh
COPY dev/litespeed/start-services.sh /usr/local/bin/start-services.sh
COPY --from=builder /out/certkit-agent /usr/local/bin/certkit-agent

RUN chmod +x /usr/local/bin/run-certkit-agent.sh \
  && chmod +x /usr/local/bin/start-services.sh

EXPOSE 8088 7080 8443

CMD ["/usr/local/bin/start-services.sh"]
