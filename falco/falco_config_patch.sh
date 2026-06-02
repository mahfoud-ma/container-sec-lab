#!/usr/bin/env bash

set -euo pipefail

CFG=/etc/falco/falco.yaml

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root" >&2
  exit 1
fi

if [[ ! -f "$CFG" ]]; then
  echo "Falco configuration file not found at $CFG; is Falco installed?" >&2
  exit 1
fi

echo "[+] Backing up Falco config to $CFG.bak"
cp "$CFG" "$CFG.bak"

sed -i 's/^json_output: false/json_output: true/' "$CFG"

if ! grep -q '^file_output:' "$CFG"; then
  cat >> "$CFG" <<'EOF'
file_output:
  enabled: true
  keep_alive: false
  filename: /var/log/falco.json
EOF
else
  sed -i 's/^  enabled: false/  enabled: true/' "$CFG"
  sed -i 's#^  filename: .*#  filename: /var/log/falco.json#' "$CFG"
fi

echo "[+] Falco configuration patched for JSON output.  Restart Falco for changes to take effect."