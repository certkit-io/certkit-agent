FROM golang:1.24

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    apache2 \
    curl \
    openssl \
  && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/apache2/ssl
RUN openssl req -x509 -nodes -newkey rsa:2048 \
  -subj "/CN=localhost" \
  -keyout /etc/apache2/ssl/certkit.key \
  -out /etc/apache2/ssl/certkit.crt \
  -days 1

COPY dev/apache/certkit.conf /etc/apache2/sites-available/certkit-ssl.conf
COPY dev/apache/run-certkit-agent.sh /usr/local/bin/run-certkit-agent.sh
COPY dev/apache/start-services.sh /usr/local/bin/start-services.sh

RUN chmod +x /usr/local/bin/run-certkit-agent.sh \
  && chmod +x /usr/local/bin/start-services.sh \
  && a2enmod ssl \
  && a2ensite certkit-ssl.conf

EXPOSE 443

CMD ["/usr/local/bin/start-services.sh"]
