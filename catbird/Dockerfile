# =============================================================================
# Catbird Nest - Multi-stage Dockerfile
# =============================================================================
# Build: docker build -t catbird-nest .
# Run:   docker run -p 3000:3000 --env-file .env catbird-nest
# =============================================================================

# Stage 1: Build
FROM rust:1.99.1-slim-trixie@sha256:1a939748a7cbab172de91a014e3804a97af1394a8c844faa67fce9401c4e40fb AS builder

WORKDIR /app

ARG CARGO_BUILD_JOBS=2

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Source and migrations are both compile-time inputs.
# Shared contract/APNs crates resolve from the immutable Cargo.lock revisions.
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY migrations ./migrations
RUN cargo build --release --locked --bin catbird

# Stage 2: Runtime
FROM debian:13.7-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3t64 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy the binary from builder
COPY --from=builder /app/target/release/catbird /app/catbird

# Create non-root user
RUN useradd -r -s /bin/false catbird
USER catbird

# Expose ports (3000 = app, 9090 = admin/metrics)
EXPOSE 3000 9090

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

# Run the binary
ENTRYPOINT ["/app/catbird"]
