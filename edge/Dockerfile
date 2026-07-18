# CryptiQ edge — hybrid PQ handshake server.
# Build from the repo root:  docker build -f edge/Dockerfile -t cryptiq-edge .
#
# WireGuard itself runs on the HOST (kernel module), not in this container.
# The container writes the server config into /state; mount that on the host
# and bring the interface up with wg-quick. See edge/README.md.

FROM rust:1-bookworm AS build
WORKDIR /src
COPY edge/Cargo.toml edge/Cargo.lock* ./
COPY edge/src ./src
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/cryptiq-edge /usr/local/bin/cryptiq-edge

ENV CRYPTIQ_EDGE_BIND=0.0.0.0:8787 \
    CRYPTIQ_EDGE_STATE_DIR=/state \
    CRYPTIQ_EDGE_DNS=1.1.1.1

VOLUME /state
EXPOSE 8787
CMD ["cryptiq-edge"]
