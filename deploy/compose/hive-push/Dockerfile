# syntax=docker/dockerfile:1.7
FROM rust:1.95-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry --mount=type=cache,target=/usr/local/cargo/git --mount=type=cache,id=hive-push-target,target=/build/target \
    CARGO_BUILD_JOBS=3 cargo build --locked --release -p buzz-push-gateway && cp target/release/buzz-push-gateway /tmp/buzz-push-gateway
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* && useradd --system --uid 1000 buzz
COPY --from=build /tmp/buzz-push-gateway /usr/local/bin/buzz-push-gateway
USER buzz
ENTRYPOINT ["/usr/local/bin/buzz-push-gateway"]
