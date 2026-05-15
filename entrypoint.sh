#!/bin/bash
export PYTHONPATH=/app

WARP_EXCLUDED_HOSTS="${WARP_EXCLUDED_HOSTS:-cinemacity.cc,*.cinemacity.cc,cccdn.net,*.cccdn.net,strem.fun,*.strem.fun,torrentio.strem.fun,real-debrid.com,*.real-debrid.com,realdebrid.com,*.realdebrid.com,api.real-debrid.com,premiumize.me,*.premiumize.me,www.premiumize.me,alldebrid.com,*.alldebrid.com,api.alldebrid.com,debrid-link.com,*.debrid-link.com,debridlink.com,*.debridlink.com,api.debrid-link.com,torbox.app,*.torbox.app,api.torbox.app,offcloud.com,*.offcloud.com,api.offcloud.com,put.io,*.put.io,api.put.io}"
WARP_LICENSE_KEY="${WARP_LICENSE_KEY:-}"
WARP_MODE="${WARP_MODE:-warp-cli}"
WARP_PROXY_HOST="${WARP_PROXY_HOST:-127.0.0.1}"
WARP_PROXY_PORT="${WARP_PROXY_PORT:-1080}"

start_wireproxy_warp() {
    echo "Starting Cloudflare WARP via wgcf + wireproxy userspace proxy..."

    if ! command -v wgcf >/dev/null 2>&1 || ! command -v wireproxy >/dev/null 2>&1; then
        echo "wgcf or wireproxy not found. Rebuild the image with userspace WARP tools installed."
        return 1
    fi

    WARP_DIR="${WARP_DIR:-/tmp/easyproxy-warp}"
    mkdir -p "$WARP_DIR"
    cd "$WARP_DIR" || return 1

    if [ ! -f wgcf-account.toml ]; then
        yes | wgcf register --accept-tos || return 1
    fi

    if [ -n "$WARP_LICENSE_KEY" ]; then
        wgcf update --license-key "$WARP_LICENSE_KEY" || true
    fi

    rm -f wgcf-profile.conf wireproxy.conf
    wgcf generate || return 1

    cp wgcf-profile.conf wireproxy.conf
    cat >> wireproxy.conf <<EOF

[Socks5]
BindAddress = ${WARP_PROXY_HOST}:${WARP_PROXY_PORT}
EOF

    wireproxy -c wireproxy.conf > /var/log/wireproxy.log 2>&1 &

    echo "Waiting for wireproxy SOCKS5 on ${WARP_PROXY_HOST}:${WARP_PROXY_PORT}..."
    for i in $(seq 1 20); do
        if command -v nc >/dev/null 2>&1 && nc -z "$WARP_PROXY_HOST" "$WARP_PROXY_PORT"; then
            echo "WARP userspace SOCKS5 proxy is listening on ${WARP_PROXY_HOST}:${WARP_PROXY_PORT}."
            return 0
        fi
        sleep 1
    done

    echo "WARP userspace SOCKS5 proxy not detected yet; continuing startup."
    return 0
}

# --- Cloudflare WARP Setup ---
if [ "$ENABLE_WARP" = "true" ]; then
    if [ "$WARP_MODE" = "wireproxy" ]; then
        start_wireproxy_warp
    else
    echo "Starting Cloudflare WARP..."
    if [ ! -c /dev/net/tun ]; then
        echo "Warning: /dev/net/tun not found. Ensure --cap-add=NET_ADMIN and --device /dev/net/tun are used."
    fi

    warp-svc --accept-tos > /var/log/warp-svc.log 2>&1 &

    MAX_RETRIES=15
    COUNT=0
    while ! warp-cli --accept-tos status > /dev/null 2>&1; do
        echo "Waiting for warp-svc... ($COUNT/$MAX_RETRIES)"
        sleep 1
        COUNT=$((COUNT+1))
        if [ $COUNT -ge $MAX_RETRIES ]; then
            echo "Failed to start warp-svc"
            break
        fi
    done

    if [ $COUNT -lt $MAX_RETRIES ]; then
        if ! warp-cli --accept-tos status | grep -q "Registration Name"; then
            echo "Registering WARP..."
            warp-cli --accept-tos registration delete > /dev/null 2>&1 || true
            warp-cli --accept-tos registration new
        fi

        if [ -n "$WARP_LICENSE_KEY" ]; then
            echo "Setting WARP license key..."
            warp-cli --accept-tos registration license "$WARP_LICENSE_KEY"
        fi

        echo "Connecting to WARP..."

        IFS=',' read -ra WARP_EXCLUDED_HOSTS_LIST <<< "$WARP_EXCLUDED_HOSTS"
        for domain in "${WARP_EXCLUDED_HOSTS_LIST[@]}"; do
            domain="$(echo "$domain" | xargs)"
            [ -z "$domain" ] && continue
            (
                warp-cli --accept-tos tunnel host add "$domain" > /dev/null 2>&1 || \
                warp-cli --accept-tos add-excluded-domain "$domain" > /dev/null 2>&1
            ) || true
        done

        # Set mode to Proxy (SOCKS5 mode)
        warp-cli --accept-tos mode proxy
        # Set proxy port to 1080
        warp-cli --accept-tos proxy port 1080
        
        warp-cli --accept-tos connect
        
        # Small delay for connection to stabilize
        echo "⏳ Waiting for WARP to stabilize (10s)..."
        sleep 10
        
        # Check if SOCKS5 proxy is actually listening
        if command -v nc >/dev/null 2>&1 && nc -z 127.0.0.1 1080; then
            echo "✅ WARP SOCKS5 proxy is listening on port 1080."
        else
            echo "⚠️ WARP SOCKS5 proxy not detected on port 1080 yet, but proceeding..."
        fi
        
        warp-cli --accept-tos status

    fi
    fi
fi

PROXY_VARS=""
SOLVERS_FORCE_WARP_PROXY="${SOLVERS_FORCE_WARP_PROXY:-false}"
if [ "$ENABLE_WARP" = "true" ] && [ "$SOLVERS_FORCE_WARP_PROXY" = "true" ]; then
    PROXY_VARS="HTTP_PROXY=socks5://${WARP_PROXY_HOST}:${WARP_PROXY_PORT} HTTPS_PROXY=socks5://${WARP_PROXY_HOST}:${WARP_PROXY_PORT} NO_PROXY=localhost,127.0.0.1"
    echo "FlareSolverr forced to use WARP SOCKS5 proxy globally: socks5://${WARP_PROXY_HOST}:${WARP_PROXY_PORT}"
else
    echo "FlareSolverr will use per-request routing from EasyProxy (supports real warp=off bypass)."
fi

echo "Starting FlareSolverr (v3 Python)..."
cd /app/flaresolverr && eval $PROXY_VARS PORT=8191 python3 src/flaresolverr.py > /dev/null &

echo "Starting EasyProxy..."
cd /app
WORKERS_COUNT=${WORKERS:-1}
gunicorn --bind 0.0.0.0:${PORT:-7860} --workers $WORKERS_COUNT --worker-class aiohttp.worker.GunicornWebWorker --timeout 120 --graceful-timeout 120 app:app
