FROM golang:1.24

ENV DEBIAN_FRONTEND=noninteractive
ENV container=docker

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    nginx \
    openssl \
    systemd \
    systemd-sysv \
  && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/nginx/ssl \
  && openssl req -x509 -nodes -newkey rsa:2048 \
    -subj "/CN=localhost" \
    -keyout /etc/nginx/ssl/certkit.key \
    -out /etc/nginx/ssl/certkit.crt \
    -days 1

COPY dev/systemd/nginx-certkit.conf /etc/nginx/sites-available/certkit.conf
COPY dev/systemd/bootstrap-certkit-agent.sh /usr/local/bin/bootstrap-certkit-agent.sh
COPY dev/systemd/certkit-agent-bootstrap.service /etc/systemd/system/certkit-agent-bootstrap.service

RUN chmod +x /usr/local/bin/bootstrap-certkit-agent.sh \
  && rm -f /etc/nginx/sites-enabled/default \
  && ln -sf /etc/nginx/sites-available/certkit.conf /etc/nginx/sites-enabled/certkit.conf \
  && ln -sf /lib/systemd/system/nginx.service /etc/systemd/system/multi-user.target.wants/nginx.service \
  && ln -sf /etc/systemd/system/certkit-agent-bootstrap.service /etc/systemd/system/multi-user.target.wants/certkit-agent-bootstrap.service

EXPOSE 443

STOPSIGNAL SIGRTMIN+3

CMD ["/sbin/init"]
