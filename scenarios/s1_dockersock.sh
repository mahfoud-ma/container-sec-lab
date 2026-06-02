#!/bin/bash
set -e

SCENARIO_NAME="s1_docker_socket_$RANDOM"
IMAGE="alpine:latest"

echo "=== S1: Docker Socket Container Escape Demo ==="
echo "Scenario: $SCENARIO_NAME"

cleanup() {
    echo "Cleaning up containers..."
    docker rm -f "$SCENARIO_NAME" >/dev/null 2>&1 || true
    docker rm -f "${SCENARIO_NAME}_victim" >/dev/null 2>&1 || true
}

cleanup
trap cleanup EXIT

echo "1. Running container with docker socket access..."
docker run --name "$SCENARIO_NAME" \
    --privileged \
    -v /var/run/docker.sock:/var/run/docker.sock \
    --rm \
    alpine:latest sh -c "
    echo 'Accessing docker socket...'
    ls -la /var/run/docker.sock
    stat /var/run/docker.sock
    echo 'Opening docker socket (triggers openat rule)...'
    cat /var/run/docker.sock >/dev/null 2>&1 || true
    nc -w1 -U /var/run/docker.sock >/dev/null 2>&1 || true
    echo 'Reading sensitive host paths via socket mount...'
    cat /proc/1/environ 2>/dev/null | tr '\0' '\n' | head -5 || true
    sleep 1
"

echo "=== S1 Complete ==="
