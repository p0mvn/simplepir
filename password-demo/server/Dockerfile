# Build stage
FROM rust:1.83-slim-bookworm AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace files
COPY password-demo/hibp ./hibp
COPY password-demo/server ./server

WORKDIR /app/server

# Build release binary
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/server/target/release/hibp-server /app/hibp-server

# Create data directory
RUN mkdir -p /app/data/ranges

# Environment defaults
ENV HIBP_DATA_DIR=/app/data/ranges
ENV PORT=3000
ENV HIBP_MEMORY_MODE=true
ENV RUST_LOG=info

EXPOSE 3000

CMD ["/app/hibp-server"]
