#!/usr/bin/env bash

set -euo pipefail

cd "$(cd "$(dirname "$0")" && pwd)"

echo "[+] Updating package index"
sudo apt-get update -y

echo "[+] Installing system tools (curl, jq, bpftrace, headers, python venv)"
sudo apt-get install -y \
  curl jq bpftrace \
  linux-headers-"$(uname -r)" \
  python3 python3-venv python3-pip

if ! command -v docker >/dev/null 2>&1; then
    echo "[+] Installing Docker"
    curl -fsSL https://get.docker.com | sh
    sudo usermod -aG docker "$USER"
else
    echo "[=] Docker already installed: $(docker --version)"
fi

if ! command -v falco >/dev/null 2>&1; then
    echo "[+] Installing Falco"
    curl -fsSL https://falco.org/install.sh | sudo sh
else
    echo "[=] Falco already installed: $(falco --version 2>&1 | head -1)"
fi

echo "[+] Creating project Python virtualenv at ./venv"
if [ -d venv ] && [ ! -x venv/bin/python3 ]; then
    echo "    Existing venv is broken (likely a Python version upgrade) — recreating"
    rm -rf venv
fi
if [ ! -d venv ]; then
    python3 -m venv venv
fi
venv/bin/pip install --upgrade --quiet pip
venv/bin/pip install --quiet -r requirements.txt

echo
echo "[=] Setup complete."
echo "[=]   - If Docker was just installed, log out and back in to pick up group membership."
echo "[=]   - Verify: docker run --rm hello-world  &&  sudo falco --version"
echo "[=]   - Run a smoke test: sudo bash run_experiment.sh quick"
