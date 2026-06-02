#!/bin/bash
set -e

SCENARIO_NAME="e2_unshare_$RANDOM"

echo "=== E2: unshare Evasion ==="
echo "Scenario: $SCENARIO_NAME"

cleanup() {
    docker rm -f "$SCENARIO_NAME" >/dev/null 2>&1 || true
}
cleanup
trap cleanup EXIT

echo "1. Running privileged container using unshare instead of nsenter..."
docker run --name "$SCENARIO_NAME" \
    --privileged \
    --pid=host \
    --rm \
    ubuntu:22.04 bash -c "
    echo '[E2] Using unshare to create new namespaces...'
    unshare --mount --uts --ipc --net -- hostname 2>/dev/null || echo 'unshare attempted'

    echo '[E2] Also trying unshare with fork...'
    unshare --fork --mount --uts -- /bin/sh -c 'hostname' 2>/dev/null || echo 'unshare fork attempted'

    sleep 1
"

echo "=== E2 Complete ==="
