#!/bin/bash
set -e

SCENARIO_NAME="e6_startup_$RANDOM"

echo "=== E6: Startup Timing Evasion ==="
echo "Scenario: $SCENARIO_NAME"

cleanup() {
    docker rm -f "$SCENARIO_NAME" >/dev/null 2>&1 || true
}
cleanup
trap cleanup EXIT

echo "1. Running container that immediately accesses docker.sock on startup..."
docker run --name "$SCENARIO_NAME" \
    --privileged \
    -v /var/run/docker.sock:/var/run/docker.sock \
    --rm \
    alpine:latest sh -c "
    cat /var/run/docker.sock >/dev/null 2>&1 || true
    sleep 1
"

echo "=== E6 Complete ==="
