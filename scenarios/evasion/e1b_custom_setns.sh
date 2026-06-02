#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
JOIN_NS="$ROOT_DIR/scenarios/evasion/helpers/join_ns"

if [ ! -f "$JOIN_NS" ]; then
    echo "ERROR: Pre-compiled binary not found at $JOIN_NS"
    echo "Build it: gcc -static -o scenarios/evasion/helpers/join_ns scenarios/evasion/helpers/join_ns.c"
    exit 1
fi

SCENARIO_NAME="e1b_csetns_$RANDOM"

echo "=== E1b: Custom C Binary setns() Evasion ==="
echo "Scenario: $SCENARIO_NAME"

cleanup() {
    docker rm -f "$SCENARIO_NAME" >/dev/null 2>&1 || true
}
cleanup
trap cleanup EXIT

echo "1. Running privileged container with pre-compiled join_ns binary..."
docker run --name "$SCENARIO_NAME" \
    --privileged \
    --pid=host \
    -v "$JOIN_NS":/tmp/join_ns:ro \
    --rm \
    alpine:latest sh -c "
    echo '[E1b] Executing custom binary /tmp/join_ns (calls setns() directly)...'
    /tmp/join_ns 2>/dev/null || echo 'join_ns attempted'

    sleep 1
"

echo "=== E1b Complete ==="
