# syntax=docker/dockerfile:1
#
# Builds dratchetd (server/README.md) as a statically-linked musl binary and
# ships it in a minimal Alpine runtime image. The whole workspace is pure
# Rust with no native/C dependencies (no openssl, no ring, nothing needing a
# C compiler at build time), so a musl build needs nothing beyond the Rust
# toolchain itself — matching the project's "no system dependencies" design.
#
# Build:  docker build -t dratchet-server:local .
# Run:    docker run --rm -p 8787:8787 dratchet-server:local
#
# Multi-stage, with a dependency-only pre-build layer so editing application
# code doesn't force re-downloading/re-compiling every crate dependency.

FROM rust:1-alpine AS builder
WORKDIR /build

RUN apk add --no-cache musl-dev

# --- Dependency layer: cached as long as Cargo.toml/Cargo.lock don't change ---
COPY Cargo.toml Cargo.lock ./
COPY core/Cargo.toml core/Cargo.toml
COPY server/Cargo.toml server/Cargo.toml
RUN mkdir -p core/src server/src \
    && echo "fn main() {}" > server/src/main.rs \
    && touch core/src/lib.rs server/src/lib.rs \
    && cargo build --release -p dratchet-server \
    && rm -rf core/src server/src

# --- Application layer: only re-compiles dratchet-core/dratchet-server themselves ---
COPY core core
COPY server server
RUN touch core/src/lib.rs server/src/lib.rs server/src/main.rs \
    && cargo build --release -p dratchet-server \
    && cp target/release/dratchetd /build/dratchetd

FROM alpine:3.20 AS runtime
RUN addgroup -S dratchet && adduser -S -G dratchet -u 10001 dratchet
COPY --from=builder /build/dratchetd /usr/local/bin/dratchetd
USER dratchet
EXPOSE 8787
ENV DRATCHETD_BIND=0.0.0.0:8787
ENTRYPOINT ["/usr/local/bin/dratchetd"]
