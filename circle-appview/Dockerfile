# =============================================================================
# Circle AppView - Multi-stage Dockerfile
# =============================================================================

# Stage 1: Build
FROM rust:1.90-slim-bookworm AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace dependencies
COPY catbird-atproto ./catbird-atproto
COPY nest/circle-appview ./nest/circle-appview

WORKDIR /app/nest/circle-appview

# Build the binary
RUN cargo build --release

# Stage 2: Runtime
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
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
