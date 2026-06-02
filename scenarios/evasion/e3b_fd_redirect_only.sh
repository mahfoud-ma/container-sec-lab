#!/bin/bash
set -e

SCENARIO_NAME="e3b_fdredirect_$RANDOM"

echo "=== E3b: Docker Socket FD-Redirect-Only Evasion ==="
echo "Scenario: $SCENARIO_NAME"

cleanup() {
    docker rm -f "$SCENARIO_NAME" >/dev/null 2>&1 || true
}
cleanup
trap cleanup EXIT

echo "1. Running container with docker socket mounted at /tmp/s..."
docker run --name "$SCENARIO_NAME" \
    --privileged \
    -v /var/run/docker.sock:/tmp/s \
    --rm \
    alpine:latest sh -c "
    echo '[E3b] Opening aliased socket to fd 3, then reading via /dev/fd/3...'
    exec 3</tmp/s 2>/dev/null || true
    cat /dev/fd/3 >/dev/null 2>&1 || true
    exec 3>&- 2>/dev/null || true

    sleep 1
"

echo "=== E3b Complete ==="
