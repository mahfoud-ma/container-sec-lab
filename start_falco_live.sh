#!/bin/bash

set -e

echo "=========================================="
echo "Starting Falco Live Monitoring"
echo "=========================================="
echo ""

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"

sudo chown -R "$USER:$USER" "$REPO_ROOT/results/" 2>/dev/null || true
mkdir -p "$REPO_ROOT/results"

: > "$REPO_ROOT/results/falco_live.jsonl"

sudo pkill -9 falco 2>/dev/null || true
sudo systemctl stop falco 2>/dev/null || true
sleep 1

echo "Starting Falco with custom rules..."
echo "Output file: results/falco_live.jsonl"
echo ""
echo "Open another terminal and run:"
echo "  bash watch_events.sh"
echo ""

cd "$REPO_ROOT"

sudo falco \
  -r /etc/falco/falco_rules.yaml \
  -r /etc/falco/falco_rules.local.yaml \
  -r falco/rules.d/05-container-activity.yaml \
  -r falco/rules.d/10-dockersock.yaml \
  -r falco/rules.d/20-host-mount-write.yaml \
  -r falco/rules.d/30-setns-or-nsenter.yaml \
  -o json_output=true \
  -o time_format_iso_8601=true \
  -o file_output.enabled=true \
  -o "file_output.filename=$(pwd)/results/falco_live.jsonl" \
  -o stdout_output.enabled=false \
  -o syslog_output.enabled=false \
  -o buffered_outputs=false \
  -o http_output.enabled=true \
  -o http_output.url=http://localhost:2801 \
  -o rule_matching=all
