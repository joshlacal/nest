# =============================================================================
# Circle AppView - Multi-stage Dockerfile
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

# Copy only this service; shared contracts resolve from the locked Git revision.
COPY nest/circle-appview ./nest/circle-appview

WORKDIR /app/nest/circle-appview

# Build the binary
RUN cargo build --release --locked

# Stage 2: Runtime
FROM debian:13.7-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3t64 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy the binary and migrations from builder
COPY --from=builder /app/nest/circle-appview/target/release/circle-appview /app/circle-appview
COPY --from=builder /app/nest/circle-appview/migrations /app/migrations

# Create non-root user
RUN useradd -r -s /bin/false catbird
USER catbird

EXPOSE 3002

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3002/_health || exit 1

ENTRYPOINT ["/app/circle-appview"]
