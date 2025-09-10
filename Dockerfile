# RAVN Security Platform Docker Container
FROM ubuntu:22.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV RAVN_VERSION=latest

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    clang \
    make \
    redis-server \
    libbpf-dev \
    libhiredis-dev \
    python3 \
    python3-pip \
    python3-venv \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy source code
COPY . .

# Set up Python environment and build RAVN
RUN python3 -m venv venv && \
    . venv/bin/activate && \
    pip install --upgrade pip && \
    pip install -r requirements.txt && \
    mkdir -p src/daemon/codegen && \
    make clean-ci && \
    make version-update && \
    make all

# Create ravn user for security
RUN useradd -r -s /bin/false ravn && \
    chown -R ravn:ravn /app

# Expose Redis port (optional)
EXPOSE 6379

# Create startup script
RUN echo '#!/bin/bash\n\
# Start Redis in background\n\
redis-server --daemonize yes\n\
\n\
# Wait for Redis to be ready\n\
while ! redis-cli ping > /dev/null 2>&1; do\n\
    echo "Waiting for Redis..."\n\
    sleep 1\n\
done\n\
\n\
echo "Redis is ready!"\n\
\n\
# Start RAVN daemon\n\
echo "Starting RAVN Security Platform..."\n\
exec ./artifacts/ravn daemon\n\
' > /app/start.sh && chmod +x /app/start.sh

# Switch to ravn user
USER ravn

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD redis-cli ping || exit 1

# Default command
CMD ["/app/start.sh"]

# Labels
LABEL maintainer="RAVN Security Platform"
LABEL description="Real-time security monitoring with eBPF and AI threat detection"
LABEL version="${RAVN_VERSION}"
