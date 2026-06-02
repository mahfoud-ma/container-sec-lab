#!/bin/bash

set -e

cd "$(cd "$(dirname "$0")" && pwd)"

MODE="${1:-quick}"

case "$MODE" in
    quick)
        RUNS=1
        HARNESS_MODE=custom
        BANNER="Quick smoke test (1 run × 3 scenarios, custom rules)"
        ;;
    full)
        RUNS=10
        HARNESS_MODE=both
        BANNER="Full experiment (10 runs × 3 scenarios × baseline+custom, ~30 min)"
        echo "$BANNER"
        if [ -t 0 ]; then
            read -p "Continue? (y/n) " -n 1 -r
            echo
            [[ ! $REPLY =~ ^[Yy]$ ]] && { echo "Cancelled."; exit 0; }
        else
            echo "(non-interactive stdin — proceeding)"
        fi
        ;;
    *)
        echo "Usage: $0 {quick|full}"
        exit 1
        ;;
esac

echo "=================================================="
echo "  $BANNER"
echo "=================================================="

echo "[1/2] Stopping any running Falco..."
sudo systemctl stop falco 2>/dev/null || true
sudo pkill -9 falco 2>/dev/null || true
sleep 1

echo "[2/2] Running experiments..."
venv/bin/python3 experiments/run_experiments.py --runs "$RUNS" --mode "$HARNESS_MODE"

if [ "$MODE" = "full" ]; then
    LATEST=$(ls -t results/runs/ 2>/dev/null | head -1)
    if [ -n "$LATEST" ] && [ -f "results/summary_${LATEST}.csv" ]; then
        echo
        echo "Latest run: $LATEST"
        echo "Quick summary:"
        column -t -s, "results/summary_${LATEST}.csv" | head -20
        echo
        echo "Full results: results/runs/$LATEST/"
    fi
fi

echo "Done."
