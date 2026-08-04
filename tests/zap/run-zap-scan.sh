#!/usr/bin/env bash
# =============================================================================
# KMS ZAP Security Scan Orchestration Script
# =============================================================================
# Runs OWASP ZAP against the KMS REST API for automated security scanning.
#
# Usage:
#   ./tests/zap/run-zap-scan.sh [baseline|api-scan]
#
#   baseline  - Passive scan only (~2-5 min, suitable for CI)
#   api-scan  - Active scan with OpenAPI import (~15-30 min)
#
# Prerequisites:
#   - Docker installed and running
#   - KMS binary built: cargo build --release (or debug)
#   - ZAP Docker image: docker pull ghcr.io/zaproxy/zaproxy-stable
#
# Environment variables:
#   KMS_BINARY    - Path to KMS binary (default: target/release/kms)
#   KMS_API_KEY   - API key for the KMS (default: auto-generated)
#   ZAP_IMAGE     - ZAP Docker image (default: ghcr.io/zaproxy/zaproxy-stable)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
REPORTS_DIR="$SCRIPT_DIR/reports"
CONFIG_DIR="$SCRIPT_DIR"

# --- Configuration ---
KMS_BINARY="${KMS_BINARY:-$PROJECT_DIR/target/release/kms}"
KMS_CONFIG="$CONFIG_DIR/kms-zap.toml"
KMS_PORT="${KMS_PORT:-8080}"
# owasp/zap2docker-* 已停更下架，官方镜像迁至 GHCR
ZAP_IMAGE="${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:stable}"
ZAP_PORT="${ZAP_PORT:-8090}"
SCAN_MODE="${1:-baseline}"

# Generate a random API key if not provided
KMS_API_KEY="${KMS_API_KEY:-zap-test-key-$(date +%s)-$(openssl rand -hex 4 2>/dev/null || echo $RANDOM)}"

# Log with timestamp
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

# Cleanup on exit
cleanup() {
    log "Cleaning up..."
    if [ -n "${KMS_PID:-}" ]; then
        kill "$KMS_PID" 2>/dev/null || true
        wait "$KMS_PID" 2>/dev/null || true
    fi
    if [ -n "${ZAP_CONTAINER:-}" ]; then
        docker rm -f "$ZAP_CONTAINER" 2>/dev/null || true
    fi
    # Remove temp config
    rm -f "$CONFIG_DIR/zap-run-config.yaml"
}
trap cleanup EXIT INT TERM

# --- Validate prerequisites ---
if [ ! -f "$KMS_BINARY" ]; then
    log "KMS binary not found at $KMS_BINARY, trying debug build..."
    KMS_BINARY="$PROJECT_DIR/target/debug/kms"
    if [ ! -f "$KMS_BINARY" ]; then
        log "ERROR: KMS binary not found. Build it first: cargo build"
        exit 1
    fi
fi

if ! command -v docker &> /dev/null; then
    log "ERROR: Docker is required but not found"
    exit 1
fi

# --- Select ZAP config ---
case "$SCAN_MODE" in
    baseline)
        ZAP_CONFIG="$CONFIG_DIR/zap-baseline.yaml"
        ZAP_JOB_NAME="baseline-scan"
        ;;
    api-scan|active)
        ZAP_CONFIG="$CONFIG_DIR/zap-api-scan.yaml"
        ZAP_JOB_NAME="api-scan"
        ;;
    *)
        log "ERROR: Unknown scan mode '$SCAN_MODE'. Use 'baseline' or 'api-scan'."
        exit 1
        ;;
esac

if [ ! -f "$ZAP_CONFIG" ]; then
    log "ERROR: ZAP config not found at $ZAP_CONFIG"
    exit 1
fi

# --- Prepare reports directory ---
mkdir -p "$REPORTS_DIR"

# --- Start KMS server ---
log "Starting KMS server on port $KMS_PORT..."
export KMS_API_KEY
KMS_API_KEY="$KMS_API_KEY" "$KMS_BINARY" \
    --server \
    --config "$KMS_CONFIG" \
    --rest-port "$KMS_PORT" &
KMS_PID=$!

# Wait for KMS to be ready
log "Waiting for KMS health check..."
for i in $(seq 1 60); do
    if curl -s "http://localhost:$KMS_PORT/healthz" > /dev/null 2>&1; then
        log "KMS is ready (attempt $i)"
        break
    fi
    if [ "$i" -eq 60 ]; then
        log "ERROR: KMS failed to start within 60 seconds"
        exit 1
    fi
    sleep 1
done

# Verify API key works
log "Verifying API key..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "x-api-key: $KMS_API_KEY" \
    "http://localhost:$KMS_PORT/v1/keys" 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "000" ]; then
    log "ERROR: KMS not responding"
    exit 1
fi
log "KMS API responded with HTTP $HTTP_CODE"

# --- Prepare ZAP config with target URL ---
# Replace __TARGET_URL__ with actual host.docker.internal URL (for Docker -> host networking)
TARGET_URL="http://host.docker.internal:$KMS_PORT"
sed "s|__TARGET_URL__|$TARGET_URL|g" "$ZAP_CONFIG" > "$CONFIG_DIR/zap-run-config.yaml"

# --- Run ZAP scan ---
log "Pulling ZAP Docker image..."
docker pull "$ZAP_IMAGE" --quiet 2>/dev/null || true

log "Starting ZAP $SCAN_MODE scan against $TARGET_URL..."

# Run ZAP with the automation config
# Mount the config directory so ZAP can access config and write reports
ZAP_CONTAINER="kms-zap-$ZAP_JOB_NAME-$$"

docker run --rm \
    --name "$ZAP_CONTAINER" \
    -v "$CONFIG_DIR:/zap/wrk:rw" \
    -v "$REPORTS_DIR:/zap/wrk/reports:rw" \
    -e "KMS_API_KEY=$KMS_API_KEY" \
    "$ZAP_IMAGE" \
    zap.sh -cmd -autorun /zap/wrk/zap-run-config.yaml \
    -addoninstall pscanrulesBeta \
    -addoninstall ascanrulesBeta 2>&1 | while IFS= read -r line; do
        echo "[ZAP] $line"
    done

ZAP_EXIT_CODE=${PIPESTATUS[0]}

# --- Collect results ---
log "ZAP scan completed with exit code: $ZAP_EXIT_CODE"

# ZAP writes reports to /zap/wrk/reports inside the container, which maps to REPORTS_DIR
if [ -d "$REPORTS_DIR" ]; then
    log "Reports generated in: $REPORTS_DIR"
    ls -la "$REPORTS_DIR"/
else
    log "WARNING: Reports directory not found"
fi

# --- Summary ---
log "=== ZAP $SCAN_MODE Scan Complete ==="
log "Reports: $REPORTS_DIR"
log "Target:  $TARGET_URL"

# Check for findings summary
for report_file in "$REPORTS_DIR"/*.md; do
    if [ -f "$report_file" ]; then
        ALERT_COUNT=$(grep -c "^|.*|.*High\|^|.*|.*Medium" "$report_file" 2>/dev/null || echo "0")
        log "Markdown report: $report_file ($ALERT_COUNT alert lines)"
    fi
done

exit 0
