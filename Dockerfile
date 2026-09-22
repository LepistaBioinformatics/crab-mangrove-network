# EXPERIMENTAL -- see README.md. No compatibility promise.
FROM golang:1.25-alpine AS build
WORKDIR /src
# go.mod has no require block, so there is nothing to download and no module
# cache layer worth keeping separate.
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/crab-mangrove-network ./cmd/crab-mangrove-network

FROM alpine:3.20
RUN adduser -D -u 10001 mangrove && mkdir -p /data/mangrove && chown mangrove:mangrove /data/mangrove
# The mangrove holds signing keys. It has no reason to be root, and unlike the
# proxy it mounts no Docker socket and needs no privileged operation.
USER mangrove
COPY --from=build /out/crab-mangrove-network /usr/local/bin/crab-mangrove-network
# Shipped so the service can be exercised where it actually runs, with no host
# tooling: `docker compose --profile mangrove exec -T crab-mangrove-network \
#   sh /usr/local/share/mangrove-smoke.sh`. It uses only busybox sh and wget.
COPY --from=build /src/scripts/smoke.sh /usr/local/share/mangrove-smoke.sh
ENV MANGROVE_STORE_DIR=/data/mangrove MANGROVE_LISTEN=:8090
EXPOSE 8090
ENTRYPOINT ["/usr/local/bin/crab-mangrove-network"]
