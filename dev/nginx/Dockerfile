FROM golang:1.24

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    curl \
    nginx \
    openssl \
  && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/nginx/ssl
RUN openssl req -x509 -nodes -newkey rsa:2048 \
  -subj "/CN=localhost" \
  -keyout /etc/nginx/ssl/certkit.key \
  -out /etc/nginx/ssl/certkit.crt \
  -days 1

COPY dev/nginx/certkit.conf /etc/nginx/conf.d/certkit.conf
COPY dev/nginx/run-certkit-agent.sh /usr/local/bin/run-certkit-agent.sh
COPY dev/nginx/start-services.sh /usr/local/bin/start-services.sh

RUN chmod +x /usr/local/bin/run-certkit-agent.sh \
  && chmod +x /usr/local/bin/start-services.sh

EXPOSE 443

CMD ["/usr/local/bin/start-services.sh"]
