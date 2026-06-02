#!/bin/bash
set -e

SCENARIO_NAME="e4_symmount_$RANDOM"
HOST_SCRATCH="/tmp/e4_scratch_$RANDOM"

echo "=== E4: Host Mount Write via Symlink Evasion ==="
echo "Scenario: $SCENARIO_NAME"

cleanup() {
    docker rm -f "$SCENARIO_NAME" >/dev/null 2>&1 || true
    rm -rf "$HOST_SCRATCH" 2>/dev/null || true
}
cleanup
trap cleanup EXIT

echo "1. Creating host scratch directory: $HOST_SCRATCH"
mkdir -p "$HOST_SCRATCH"

echo "2. Running container with HOST ROOT mounted at /hostroot..."
docker run --name "$SCENARIO_NAME" \
    -v /:/hostroot:rw \
    --rm \
    alpine:latest sh -c "
    echo '[E4a] Direct write to mounted host path (baseline)...'
    echo 'direct-write-payload' > /hostroot${HOST_SCRATCH}/direct_test.txt

    echo '[E4b] Creating symlink to mounted host path...'
    ln -s /hostroot${HOST_SCRATCH} /tmp/host_link

    echo '[E4b] Writing through symlink (evasion attempt)...'
    echo 'symlink-write-payload' > /tmp/host_link/symlink_test.txt

    echo '[E4c] Creating nested symlink chain...'
    ln -s /tmp/host_link /tmp/host_link2
    echo 'nested-symlink-payload' > /tmp/host_link2/nested_test.txt

    sleep 1
"

echo "3. Verifying writes landed on host..."
if [ -f "$HOST_SCRATCH/direct_test.txt" ] && \
   [ -f "$HOST_SCRATCH/symlink_test.txt" ] && \
   [ -f "$HOST_SCRATCH/nested_test.txt" ]; then
    echo "   All 3 payloads confirmed on host filesystem."
else
    echo "   WARNING: Some payloads missing — check mount."
    ls -la "$HOST_SCRATCH/" 2>/dev/null || true
fi

echo "=== E4 Complete ==="
