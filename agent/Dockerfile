# syntax=docker/dockerfile:1.7
#
# Builds the agent as a statically linked musl binary in a `scratch` image.
#
# Why cross-compile rather than build under emulation: there is no
# `linux/arm/v7` variant of `rust:alpine`, so a QEMU-emulated native build has
# no base image to run on. cargo-zigbuild uses Zig as the linker, which ships
# musl headers for every target, so the whole build runs natively on the build
# host and stays fast.
#
# The result has no libc, no shell, and no package manager — nothing to patch
# and nothing for an attacker to pivot into. That matters on a device where
# MikroTik's own documentation warns a compromised container is a route to
# elevating on the router.

ARG RUST_VERSION=1.98
# armv7 (32-bit ARM, hard-float) — hAP ac³, RB4011 and similar.
# For ARM64 devices (RB5009, CCR2004, cAP ax) pass:
#   --build-arg TARGET=aarch64-unknown-linux-musl
ARG TARGET=armv7-unknown-linux-musleabihf

FROM --platform=$BUILDPLATFORM rust:${RUST_VERSION}-bookworm AS builder
ARG TARGET

RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-pip \
 && rm -rf /var/lib/apt/lists/*

# Zig provides the cross-linker and musl headers.
RUN pip3 install --break-system-packages --no-cache-dir ziglang

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo install cargo-zigbuild --locked

RUN rustup target add ${TARGET}

WORKDIR /build

# Dependencies first, so editing agent source does not re-download and rebuild
# the whole tree.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
 && echo 'fn main() {}' > src/main.rs \
 && echo '' > src/lib.rs \
 && cargo zigbuild --release --locked --target ${TARGET} 2>/dev/null || true \
 && rm -rf src

COPY src ./src

# Touch the real sources so cargo rebuilds them rather than reusing the stub
# fingerprints from the dependency layer above.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    touch src/main.rs src/lib.rs \
 && cargo zigbuild --release --locked --target ${TARGET} \
 && cp target/${TARGET}/release/mqagent /mqagent

# Fail the build rather than ship a binary that will not start on the router:
# a dynamically linked binary has nothing to link against in `scratch`.
RUN set -eu; \
    if head -c 4 /mqagent | grep -q ELF; then :; else echo "not an ELF binary"; exit 1; fi; \
    if readelf -l /mqagent 2>/dev/null | grep -q "INTERP"; then \
        echo "ERROR: binary is dynamically linked; it cannot run in a scratch image"; \
        exit 1; \
    fi; \
    echo "static binary OK: $(stat -c %s /mqagent) bytes"

FROM scratch
COPY --from=builder /mqagent /mqagent

# Probe port. RouterOS maps this through the veth; see docs/deployment-mikrotik.md.
EXPOSE 5301/udp

# Config comes from environment variables set via `/container/envs` on the
# router — a scratch image has no convenient way to manage a config file, and
# envlists are how RouterOS expects containers to be parameterised.
ENV MQ_PROBE_PORT=5301 \
    MQ_LOG=info

ENTRYPOINT ["/mqagent"]
