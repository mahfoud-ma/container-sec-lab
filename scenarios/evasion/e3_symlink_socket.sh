#!/bin/bash
set -e

SCENARIO_NAME="e3_symlink_$RANDOM"

echo "=== E3: Docker Socket Symlink/FD Evasion ==="
echo "Scenario: $SCENARIO_NAME"

cleanup() {
    docker rm -f "$SCENARIO_NAME" >/dev/null 2>&1 || true
}
cleanup
trap cleanup EXIT

echo "1. Running container with docker socket — testing symlink access..."
docker run --name "$SCENARIO_NAME" \
    --privileged \
    -v /var/run/docker.sock:/var/run/docker.sock \
    --rm \
    alpine:latest sh -c "
    echo '[E3a] Creating symlink to docker.sock...'
    ln -s /var/run/docker.sock /tmp/sock-link

    echo '[E3a] Accessing docker.sock via symlink (cat /tmp/sock-link)...'
    cat /tmp/sock-link >/dev/null 2>&1 || true

    echo '[E3b] Accessing docker.sock via file descriptor technique...'
    exec 3</var/run/docker.sock 2>/dev/null || true
    cat /dev/fd/3 >/dev/null 2>&1 || true
    exec 3>&- 2>/dev/null || true

    echo '[E3c] Accessing docker.sock via /proc/self/fd after opening...'
    cat /var/run/docker.sock >/dev/null 2>&1 &
    BGPID=\$!
    ls -la /proc/\$BGPID/fd/ 2>/dev/null || true
    wait \$BGPID 2>/dev/null || true

    sleep 1
"

echo "=== E3 Complete ==="
