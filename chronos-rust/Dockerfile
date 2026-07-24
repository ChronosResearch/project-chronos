# ------------------------------------------------------------------------------
# STAGE 1: Builder
# ------------------------------------------------------------------------------
FROM rust:slim-bullseye AS builder

# Install build dependencies required for compiling the cryptography
RUN apt-get update && \
    apt-get install -y pkg-config libssl-dev build-essential && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/chronos

# Copy over the entire workspace
COPY . .

# Build the Chronos Agent orchestrator binary in release mode
RUN cargo build --release --bin chronos-agent

# ------------------------------------------------------------------------------
# STAGE 2: Production Runtime
# ------------------------------------------------------------------------------
FROM debian:bullseye-slim

# Install runtime dependencies (OpenSSL is needed for the Drand client / reqwest)
RUN apt-get update && \
    apt-get install -y ca-certificates libssl1.1 && \
    rm -rf /var/lib/apt/lists/*

# Create a non-root user for security
RUN useradd -m -s /bin/bash chronos_user
USER chronos_user
WORKDIR /home/chronos_user

# Copy the compiled binary from the builder stage
COPY --from=builder /usr/src/chronos/target/release/chronos-agent /usr/local/bin/chronos-agent

# Set the entrypoint to the agent orchestrator
ENTRYPOINT ["chronos-agent"]
