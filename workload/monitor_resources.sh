#!/bin/bash

set -u

OUTPUT=${1:?usage: monitor_resources.sh <output.csv> [interval_sec]}
INTERVAL=${2:-1}

echo "timestamp_ns,cpu_pct,mem_rss_kb,mem_vsz_kb" > "${OUTPUT}"

while true; do
    TS=$(date +%s%N)
    FALCO_PID=$(pgrep -x falco | head -1)
    if [ -n "${FALCO_PID}" ]; then
        read -r CPU RSS VSZ < <(ps -p "${FALCO_PID}" -o %cpu=,rss=,vsz= 2>/dev/null)
        if [ -n "${CPU}" ] && [ -n "${RSS}" ] && [ -n "${VSZ}" ]; then
            echo "${TS},${CPU},${RSS},${VSZ}" >> "${OUTPUT}"
        fi
    fi
    sleep "${INTERVAL}"
done
