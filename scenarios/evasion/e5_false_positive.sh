#!/bin/bash
set -e

DURATION=${1:-300}
NGINX_NAME="e5_nginx_$RANDOM"
POSTGRES_NAME="e5_postgres_$RANDOM"
PG_PASSWORD="testpass123"

echo "=== E5: False Positive Baseline Test ==="
echo "Duration: ${DURATION}s"
echo "Containers: nginx + postgres under light load"

cleanup() {
    echo "Cleaning up..."
    docker rm -f "$NGINX_NAME" "$POSTGRES_NAME" >/dev/null 2>&1 || true
}
cleanup
trap cleanup EXIT

docker pull nginx:alpine >/dev/null 2>&1 || true

echo "1. Starting nginx container..."
docker run -d --name "$NGINX_NAME" \
    -p 8099:80 \
    nginx:alpine >/dev/null

echo "2. Starting postgres container..."
docker run -d --name "$POSTGRES_NAME" \
    -e POSTGRES_PASSWORD="$PG_PASSWORD" \
    -p 5499:5432 \
    postgres:15-alpine >/dev/null

echo "3. Waiting 10s for containers to initialize..."
sleep 10

echo "4. Starting light load generation for ${DURATION}s..."

(
    end_time=$((SECONDS + DURATION))
    while [ $SECONDS -lt $end_time ]; do
        for i in 1 2 3 4 5; do
            curl -s -o /dev/null http://localhost:8099/ 2>/dev/null || true
            curl -s -o /dev/null http://localhost:8099/nonexistent 2>/dev/null || true
        done
        sleep 10
    done
) &
NGINX_LOAD_PID=$!

(
    end_time=$((SECONDS + DURATION))
    sleep 5
    while [ $SECONDS -lt $end_time ]; do
        docker exec "$POSTGRES_NAME" psql -U postgres -c "SELECT 1;" >/dev/null 2>&1 || true
        docker exec "$POSTGRES_NAME" psql -U postgres -c "CREATE TABLE IF NOT EXISTS test_fp (id serial, data text);" >/dev/null 2>&1 || true
        docker exec "$POSTGRES_NAME" psql -U postgres -c "INSERT INTO test_fp (data) VALUES ('test_$(date +%s)');" >/dev/null 2>&1 || true
        docker exec "$POSTGRES_NAME" psql -U postgres -c "SELECT count(*) FROM test_fp;" >/dev/null 2>&1 || true
        sleep 15
    done
) &
PG_LOAD_PID=$!

echo "   Load generators running (nginx PID=$NGINX_LOAD_PID, postgres PID=$PG_LOAD_PID)"
echo "   Waiting ${DURATION}s..."

sleep "$DURATION"

kill $NGINX_LOAD_PID $PG_LOAD_PID 2>/dev/null || true
wait $NGINX_LOAD_PID $PG_LOAD_PID 2>/dev/null || true

echo "5. Load generation complete."
echo "=== E5 Complete ==="
