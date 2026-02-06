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

RUN rm -f /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/default \
  && mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled

COPY dev/nginx2/site-both.conf /etc/nginx/sites-available/site-both.conf
COPY dev/nginx2/site-enabled-only.conf /etc/nginx/sites-enabled/site-enabled-only.conf
COPY dev/nginx2/site-available-only.conf /etc/nginx/sites-available/site-available-only.conf
RUN cp /etc/nginx/sites-available/site-both.conf /etc/nginx/sites-enabled/site-both.conf

COPY dev/nginx2/run-certkit-agent.sh /usr/local/bin/run-certkit-agent.sh
COPY dev/nginx2/start-services.sh /usr/local/bin/start-services.sh

RUN chmod +x /usr/local/bin/run-certkit-agent.sh \
  && chmod +x /usr/local/bin/start-services.sh

EXPOSE 443

CMD ["/usr/local/bin/start-services.sh"]
