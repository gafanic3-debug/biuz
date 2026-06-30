# Monolithic Dockerfile for EasyProxy
# Optimized: Uses FlareSolverr v3 (Python)
# Compatible with AMD64 and ARM64 (Oracle VPS)

FROM python:3.12-slim-bookworm

# 1. Environment Settings
WORKDIR /app
ENV PYTHONUNBUFFERED=1
ENV FLARESOLVERR_URL=http://localhost:8191

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    gnupg \
    gpg \
    tar \
    nodejs \
    && curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ bookworm main" | tee /etc/apt/sources.list.d/cloudflare-client.list \
    && apt-get update && apt-get install -y --no-install-recommends \
    cloudflare-warp \
    netcat-openbsd \
    ffmpeg \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Optional userspace WARP tools. They allow WARP as a local SOCKS5 proxy
# without NET_ADMIN or /dev/net/tun when WARP_MODE=wireproxy is selected.
ARG WGCF_VERSION=2.2.29
ARG WIREPROXY_VERSION=1.0.9
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
        amd64) wgcf_arch="amd64"; wireproxy_arch="amd64" ;; \
        arm64) wgcf_arch="arm64"; wireproxy_arch="arm64" ;; \
        armhf) wgcf_arch="armv7"; wireproxy_arch="arm" ;; \
        *) echo "Unsupported architecture for wgcf/wireproxy: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fL "https://github.com/ViRb3/wgcf/releases/download/v${WGCF_VERSION}/wgcf_${WGCF_VERSION}_linux_${wgcf_arch}" -o /usr/local/bin/wgcf; \
    chmod +x /usr/local/bin/wgcf; \
    curl -fL "https://github.com/pufferffish/wireproxy/releases/download/v${WIREPROXY_VERSION}/wireproxy_linux_${wireproxy_arch}.tar.gz" -o /tmp/wireproxy.tar.gz; \
    tar -xzf /tmp/wireproxy.tar.gz -C /tmp; \
    find /tmp -type f -name wireproxy -exec mv {} /usr/local/bin/wireproxy \; ; \
    chmod +x /usr/local/bin/wireproxy; \
    rm -f /tmp/wireproxy.tar.gz

# Install Ookla Speedtest CLI for the admin panel speedtest
ARG SPEEDTEST_VERSION=1.2.0
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
        amd64) speedtest_arch="x86_64" ;; \
        arm64) speedtest_arch="aarch64" ;; \
        *) echo "Unsupported architecture for speedtest: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://install.speedtest.net/app/cli/ookla-speedtest-${SPEEDTEST_VERSION}-linux-${speedtest_arch}.tgz" -o /tmp/speedtest.tgz; \
    tar -xzf /tmp/speedtest.tgz -C /usr/local/bin speedtest; \
    chmod +x /usr/local/bin/speedtest; \
    rm -f /tmp/speedtest.tgz

# 2. EasyProxy Dependencies
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# 3. Environment Settings
ENV PYTHONPATH=/app

# Copia esplicita
COPY . .

RUN chmod +x entrypoint.sh

# 5. Metadata & Ports
LABEL org.opencontainers.image.title="EasyProxy Monolith"
LABEL org.opencontainers.image.description="All-in-one HLS Proxy with integrated CF Turnstile Solver"
EXPOSE 7860
VOLUME ["/data"]

# 6. Execution
ENTRYPOINT ["/bin/bash", "/app/entrypoint.sh"]
