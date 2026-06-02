#!/bin/bash
set -e

SCENARIO_NAME="s3_host_mount_$RANDOM"
HOST_MOUNT_DIR="/tmp/host_mount_test_$RANDOM"

echo "=== S3: Host Mount Container Escape Demo ==="
echo "Scenario: $SCENARIO_NAME"

cleanup() {
    echo "Cleaning up..."
    docker rm -f "$SCENARIO_NAME" >/dev/null 2>&1 || true
    rm -rf "$HOST_MOUNT_DIR" 2>/dev/null || true
}

cleanup
trap cleanup EXIT

echo "1. Creating host directory: $HOST_MOUNT_DIR"
mkdir -p "$HOST_MOUNT_DIR"

echo "2. Running container with host root mounted..."
docker run --name "$SCENARIO_NAME" \
    -v /:"$HOST_MOUNT_DIR" \
    --rm \
    alpine:latest sh -c "
    echo 'Mounted host root filesystem...'
    ls -la $HOST_MOUNT_DIR/ | head -10

    echo 'Attempting to write to host filesystem...'
    echo 'Container escape payload' > $HOST_MOUNT_DIR/tmp/container_escape_test_\$RANDOM.txt

    echo 'Attempting to access sensitive host files...'
    head -5 $HOST_MOUNT_DIR/etc/passwd 2>/dev/null || echo 'Cannot read /etc/passwd'
    head -5 $HOST_MOUNT_DIR/etc/shadow 2>/dev/null || echo 'Cannot read /etc/shadow'

    echo 'Creating multiple test files...'
    for i in 1 2 3; do
        echo 'test \$i' > $HOST_MOUNT_DIR/tmp/escape_test_\${i}_\$RANDOM.txt
    done

    echo 'Attempting to modify crontab...'
    echo '* * * * * echo container-escape' > $HOST_MOUNT_DIR/tmp/malicious_cron 2>/dev/null || echo 'Cannot write cron'

    sleep 1
"

echo "=== S3 Complete ==="
