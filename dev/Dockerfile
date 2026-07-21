FROM golang:1.24

# The private CA trust-store flow needs the Debian ca-certificates package:
# it provides /usr/local/share/ca-certificates and update-ca-certificates.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
