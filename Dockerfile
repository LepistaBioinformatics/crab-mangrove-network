# EXPERIMENTAL -- see README.md. No compatibility promise.
FROM golang:1.25-alpine AS build
WORKDIR /src
# go.mod has no require block, so there is nothing to download and no module
# cache layer worth keeping separate.
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/crab-reef-network ./cmd/crab-reef-network

FROM alpine:3.20
RUN adduser -D -u 10001 reef && mkdir -p /data/reef && chown reef:reef /data/reef
# The reef holds signing keys. It has no reason to be root, and unlike the
# proxy it mounts no Docker socket and needs no privileged operation.
USER reef
COPY --from=build /out/crab-reef-network /usr/local/bin/crab-reef-network
ENV REEF_STORE_DIR=/data/reef REEF_LISTEN=:8090
EXPOSE 8090
ENTRYPOINT ["/usr/local/bin/crab-reef-network"]
