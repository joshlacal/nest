# Build from the directory containing nest, Petrel and PetrelCatbird.
# docker build -f nest/catbird/Dockerfile -t catbird-nest .
FROM rust:1.100.0-slim-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev cmake && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY Petrel/rust Petrel/rust
COPY PetrelCatbird/rust/petrel-catbird PetrelCatbird/rust/petrel-catbird
COPY nest/catbird nest/catbird
WORKDIR /build/nest/catbird
RUN cargo build --locked --release --bin catbird

FROM debian:bookworm-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl3 curl && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/nest/catbird/target/release/catbird /app/catbird
COPY --from=builder /build/nest/catbird/config/default.toml /app/config/default.toml
RUN useradd -r -s /bin/false catbird
USER catbird
EXPOSE 3000 9090
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD curl -f http://localhost:3000/health || exit 1
ENTRYPOINT ["/app/catbird"]
