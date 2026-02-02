FROM golang:1.24-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags "-s -w -X main.version=$VERSION -X main.commit=$COMMIT -X main.date=$DATE" \
    -o /out/certkit-agent ./cmd/certkit-agent

FROM alpine:3.20

RUN apk add --no-cache ca-certificates

COPY --from=build /out/certkit-agent /usr/local/bin/certkit-agent

ENV CERTKIT_CONFIG_PATH=/etc/certkit-agent/config.json

ENTRYPOINT ["sh", "-c", "exec certkit-agent run --config \"$CERTKIT_CONFIG_PATH\""]
