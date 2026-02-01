FROM nginx:1.25-alpine

RUN apk add --no-cache openssl inotify-tools

COPY dev/docker-sidecar/nginx.conf /etc/nginx/conf.d/default.conf
COPY dev/docker-sidecar/nginx-start.sh /usr/local/bin/nginx-start.sh
RUN chmod +x /usr/local/bin/nginx-start.sh

ENTRYPOINT ["/usr/local/bin/nginx-start.sh"]
