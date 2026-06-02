#!/bin/bash
set -e

SCENARIO_NAME="e3a_symlink_$RANDOM"

echo "=== E3a: Docker Socket Symlink-Only Evasion ==="
echo "Scenario: $SCENARIO_NAME"

cleanup() {
    docker rm -f "$SCENARIO_NAME" >/dev/null 2>&1 || true
}
cleanup
trap cleanup EXIT

echo "1. Running container with docker socket — symlink access only..."
docker run --name "$SCENARIO_NAME" \
    --privileged \
    -v /var/run/docker.sock:/var/run/docker.sock \
    --rm \
    alpine:latest sh -c "
    echo '[E3a] Creating symlink to docker.sock...'
    ln -s /var/run/docker.sock /tmp/sock-link

    echo '[E3a] Accessing docker.sock via symlink (cat /tmp/sock-link)...'
    cat /tmp/sock-link >/dev/null 2>&1 || true

    sleep 1
"

echo "=== E3a Complete ==="
