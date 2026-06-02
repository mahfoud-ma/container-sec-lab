#!/bin/bash

set -u

DURATION=${1:-0}  # 0 = run until killed
END_TIME=0

if [ "${DURATION}" -gt 0 ]; then
    END_TIME=$((SECONDS + DURATION))
fi

while true; do
    if [ "${END_TIME}" -gt 0 ] && [ "${SECONDS}" -ge "${END_TIME}" ]; then
        break
    fi

    for _ in 1 2 3 4 5; do
        curl -s -o /dev/null http://localhost:8098/ 2>/dev/null &
    done
    wait

    if docker exec workload-db pg_isready -U postgres >/dev/null 2>&1; then
        docker exec workload-db psql -U postgres -c \
            "CREATE TABLE IF NOT EXISTS wl_test (id serial, ts timestamp default now(), data text);" \
            >/dev/null 2>&1 || true
        docker exec workload-db psql -U postgres -c \
            "INSERT INTO wl_test (data) VALUES ('noise_$(date +%s)');" \
            >/dev/null 2>&1 || true
        docker exec workload-db psql -U postgres -c \
            "SELECT count(*) FROM wl_test;" \
            >/dev/null 2>&1 || true
    fi

    sleep 5
done
