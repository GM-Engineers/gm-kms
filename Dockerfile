# =============================================================================
# gm-kms Docker Image
# Multi-stage build for minimal image size
#
# Build context should be the parent directory of gm-kms (i.e., the directory
# containing both gm-kms and gm folders).
#
# Build command: docker build -f gm-kms/Dockerfile -t gm-kms:test .
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Build
# -----------------------------------------------------------------------------
FROM rust:1.88-bookworm AS builder

WORKDIR /app

# Install build dependencies for rdkafka, gm-crypto, and GmSSL
RUN apt-get update && apt-get install -y \
    librdkafka-dev \
    libssl-dev \
    pkg-config \
    protobuf-compiler \
    cmake \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /root/.cargo/git/db \
    && mkdir -p /root/.cargo/registry/cache \
    && mkdir -p /root/.cargo/registry/index

# Build and install GmSSL 3.1.1 for SM9 GM/T 0044-2016 compliant backend
RUN git clone --depth 1 --branch v3.1.1 https://github.com/guanzhi/GmSSL.git /tmp/gmssl && \
    mkdir -p /tmp/gmssl/build && cd /tmp/gmssl/build && \
    cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=ON && \
    make -j$(nproc) && make install && \
    ldconfig && \
    rm -rf /tmp/gmssl

# Copy workspace files from gm-kms (preserving directory structure)
COPY gm-kms/Cargo.toml gm-kms/Cargo.lock ./gm-kms/
COPY gm-kms/crates ./gm-kms/crates
COPY gm-kms/src ./gm-kms/src
COPY gm-kms/examples ./gm-kms/examples

# Copy gm dependency
COPY gm ./gm

# Build release binary from the gm-kms workspace
WORKDIR /app/gm-kms
RUN cargo build --release --bin kms

# -----------------------------------------------------------------------------
# Stage 2: Runtime
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libssl3 \
    libgcc-s1 \
    ca-certificates \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -m -u 1000 kms && \
    mkdir -p /app/config && \
    chown -R kms:kms /app

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/gm-kms/target/release/kms /app/kms

# Copy GmSSL shared library from builder
COPY --from=builder /usr/local/lib/libgmssl.so* /usr/local/lib/
RUN ldconfig

# Copy config example from build context
COPY gm-kms/kms.toml.example /app/config/kms.toml.example

# Create a Docker-specific config that disables Redis
RUN echo '[redis]' > /app/config/kms-docker.toml && \
    echo 'enabled = false' >> /app/config/kms-docker.toml && \
    echo '' >> /app/config/kms-docker.toml && \
    echo '[rate_limit]' >> /app/config/kms-docker.toml && \
    echo 'enabled = false' >> /app/config/kms-docker.toml && \
    echo '' >> /app/config/kms-docker.toml && \
    echo '[quota]' >> /app/config/kms-docker.toml && \
    echo 'enabled = false' >> /app/config/kms-docker.toml

# Switch to non-root user
USER kms

# Expose ports
EXPOSE 8080 9090

# Health check - verify the process is running
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD pgrep -x kms || exit 1

# Default command - runs server mode with config that disables Redis for standalone container
ENTRYPOINT ["/app/kms"]
CMD ["--server", "--config", "/app/config/kms-docker.toml"]