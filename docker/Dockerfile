FROM golang:1.24-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

# TARGETARCH is set by buildx per platform (amd64 / arm64); default keeps
# plain `docker build` working.
ARG TARGETARCH=amd64
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=$VERSION -X main.commit=$COMMIT -X main.date=$DATE" \
    -o /out/certkit-agent ./cmd/certkit-agent

FROM alpine:3.20

# bash: the agent prefers bash (set -euo pipefail) for update commands when
# it is present. curl / jq / openssl: used by deployment templates.
# docker-cli: client only (no daemon), for the sidecar "docker exec <web>
# <reload>" mode with /var/run/docker.sock mounted.
RUN apk add --no-cache ca-certificates bash curl jq openssl docker-cli

COPY --from=build /out/certkit-agent /usr/local/bin/certkit-agent

ENV CERTKIT_CONFIG_PATH=/etc/certkit-agent/config.json

ENTRYPOINT ["sh", "-c", "exec certkit-agent run --config \"$CERTKIT_CONFIG_PATH\""]
