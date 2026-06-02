#!/bin/bash

cd "$(cd "$(dirname "$0")" && pwd)"

if [ ! -f results/falco_live.jsonl ]; then
    echo "Error: Falco not running or no events yet."
    echo "Start Falco first: bash start_falco_live.sh"
    exit 1
fi

echo "=========================================="
echo "Watching Falco Events (Ctrl+C to stop)"
echo "=========================================="
echo ""
echo "Format: TIME | PRIORITY | RULE | CONTAINER"
echo "------------------------------------------"

tail -f results/falco_live.jsonl | while read -r line; do
    TIME=$(echo "$line" | jq -r '.time // empty' 2>/dev/null)
    PRIORITY=$(echo "$line" | jq -r '.priority // empty' 2>/dev/null)
    RULE=$(echo "$line" | jq -r '.rule // empty' 2>/dev/null)
    CONTAINER=$(echo "$line" | jq -r '.output_fields.container.name // empty' 2>/dev/null)

    if [ -n "$TIME" ] && [ -n "$RULE" ]; then
        printf "%s | %-10s | %-40s | %s\n" \
            "$(date -d "$TIME" '+%H:%M:%S' 2>/dev/null || echo "$TIME" | cut -c12-19)" \
            "$PRIORITY" \
            "$RULE" \
            "$CONTAINER"
    fi
done
