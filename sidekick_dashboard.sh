#!/usr/bin/env bash

set -euo pipefail
cd "$(dirname "$0")"

COMPOSE_FILE="docker-compose.falcosidekick.yaml"
SIDEKICK_URL="http://localhost:2801"
UI_URL="http://localhost:2802"
DATASET_DIR="results"

EVASION_BATCH=""
STANDARD_BATCH=""
REPLAY_ALL=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --batch)     EVASION_BATCH="$2"; shift 2 ;;
        --standard)  STANDARD_BATCH="$2"; shift 2 ;;
        --all)       REPLAY_ALL=true; shift ;;
        -h|--help)
            echo "Usage: $0 [--batch <evasion-batch>] [--standard <standard-batch>] [--all]"
            exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [ -z "$EVASION_BATCH" ] && [ "$REPLAY_ALL" = false ]; then
    EVASION_BATCH=$(ls -d "$DATASET_DIR/evasion_runs"/2* 2>/dev/null | sort | tail -1 | xargs basename 2>/dev/null || echo "")
fi
if [ -z "$STANDARD_BATCH" ] && [ "$REPLAY_ALL" = false ]; then
    for d in $(ls -d "$DATASET_DIR/runs"/2* 2>/dev/null | sort -r); do
        if [ -d "$d/baseline" ] && [ -d "$d/custom" ]; then
            STANDARD_BATCH=$(basename "$d")
            break
        fi
    done
fi

ensure_stack() {
    if curl -s -o /dev/null -w '%{http_code}' "$SIDEKICK_URL/healthz" 2>/dev/null | grep -q "200"; then
        echo "[OK] Falcosidekick already running"
    else
        echo "[...] Starting falcosidekick stack..."
        if [ -f sidekick.sh ]; then
            bash sidekick.sh up
        else
            docker compose -f "$COMPOSE_FILE" up -d
        fi
        echo -n "    Waiting for sidekick"
        for i in $(seq 1 30); do
            if curl -s -o /dev/null "$SIDEKICK_URL/healthz" 2>/dev/null; then
                echo " ready."
                break
            fi
            echo -n "."
            sleep 1
        done
    fi

    echo -n "    Waiting for UI"
    for i in $(seq 1 30); do
        if curl -s -o /dev/null "$UI_URL" 2>/dev/null; then
            echo " ready."
            return 0
        fi
        echo -n "."
        sleep 1
    done
    echo " TIMEOUT — UI may not be available"
}

replay_jsonl() {
    local file="$1"
    local label="$2"
    local count=0
    local skipped=0

    while IFS= read -r line; do
        [ -z "$line" ] && continue
        if echo "$line" | grep -q '"Falco internal: metrics snapshot"'; then
            skipped=$((skipped + 1))
            continue
        fi

        curl -s -o /dev/null -X POST "$SIDEKICK_URL" \
            -H "Content-Type: application/json" \
            -d "$line" 2>/dev/null || true
        count=$((count + 1))
    done < "$file"

    echo "    $label: replayed $count events (skipped $skipped metrics)"
}

replay_directory() {
    local dir="$1"
    local label="$2"
    local total_files=0

    if [ ! -d "$dir" ]; then
        echo "    [SKIP] $dir not found"
        return
    fi

    for f in "$dir"/*.jsonl; do
        [ -f "$f" ] || continue
        replay_jsonl "$f" "$(basename "$f" .jsonl)"
        total_files=$((total_files + 1))
    done

    echo "    $label: $total_files files replayed"
}

echo "============================================================"
echo "  Falcosidekick Dashboard — Thesis Screenshot Helper"
echo "============================================================"
echo ""

ensure_stack
echo ""

echo "Replaying experiment data..."

if [ "$REPLAY_ALL" = true ]; then
    for d in "$DATASET_DIR/runs"/2*; do
        [ -d "$d" ] || continue
        batch=$(basename "$d")
        echo "  Standard batch: $batch"
        [ -d "$d/baseline" ] && replay_directory "$d/baseline" "baseline"
        [ -d "$d/custom" ] && replay_directory "$d/custom" "custom"
    done
    for d in "$DATASET_DIR/evasion_runs"/2*; do
        [ -d "$d" ] || continue
        batch=$(basename "$d")
        echo "  Evasion batch: $batch"
        for sub in "$d"/*/; do
            [ -d "$sub" ] || continue
            replay_directory "$sub" "$(basename "$sub")"
        done
    done
else
    if [ -n "$STANDARD_BATCH" ]; then
        echo "  Standard batch: $STANDARD_BATCH"
        sd="$DATASET_DIR/runs/$STANDARD_BATCH"
        [ -d "$sd/baseline" ] && replay_directory "$sd/baseline" "baseline"
        [ -d "$sd/custom" ] && replay_directory "$sd/custom" "custom"
    fi

    if [ -n "$EVASION_BATCH" ]; then
        echo "  Evasion batch: $EVASION_BATCH"
        ed="$DATASET_DIR/evasion_runs/$EVASION_BATCH"
        for sub in "$ed"/*/; do
            [ -d "$sub" ] || continue
            replay_directory "$sub" "$(basename "$sub")"
        done
    fi
fi

echo ""
echo "============================================================"
echo "  Dashboard URLs for Thesis Screenshots"
echo "============================================================"
echo ""
echo "  Main dashboard (all events):"
echo "    $UI_URL/ui"
echo ""
echo "  --- Filtered views (use these for targeted screenshots) ---"
echo ""
echo "  Layer 2 escape-specific alerts only:"
echo "    $UI_URL/ui/#/events?rule=Container+Docker+Socket+Access"
echo "    $UI_URL/ui/#/events?rule=Container+Calling+setns+Syscall"
echo "    $UI_URL/ui/#/events?rule=Container+Writing+Under+Mounted+Host+Root"
echo "    $UI_URL/ui/#/events?rule=Container+With+Docker+Socket+Mounted"
echo "    $UI_URL/ui/#/events?rule=Container+With+Host+Root+Mounted"
echo "    $UI_URL/ui/#/events?rule=Container+Using+nsenter"
echo "    $UI_URL/ui/#/events?rule=Container+Calling+unshare+Syscall"
echo ""
echo "  Layer 1 broad activity alerts:"
echo "    $UI_URL/ui/#/events?rule=Container+File+Activity"
echo "    $UI_URL/ui/#/events?rule=Container+Process+Spawned"
echo "    $UI_URL/ui/#/events?rule=Container+Reading+Sensitive+Paths"
echo ""
echo "  By priority:"
echo "    $UI_URL/ui/#/events?priority=Critical"
echo "    $UI_URL/ui/#/events?priority=Warning"
echo "    $UI_URL/ui/#/events?priority=Notice"
echo ""
echo "  By source/tag:"
echo "    $UI_URL/ui/#/events?tags=escape"
echo "    $UI_URL/ui/#/events?tags=docker"
echo "    $UI_URL/ui/#/events?source=syscall"
echo ""
echo "  TIP: The Falcosidekick-UI supports filtering in the top bar."
echo "       Use rule name, priority, or source to create screenshot-"
echo "       worthy views. Combine filters for more specific views."
echo ""
echo "  TIP: For the best thesis screenshots:"
echo "    1. Open a filtered URL above"
echo "    2. Adjust the time window to show the experiment period"
echo "    3. Use the browser's full-screen mode (F11)"
echo "    4. Screenshot with: gnome-screenshot -a  (area select)"
echo ""
echo "============================================================"
