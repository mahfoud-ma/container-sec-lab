#!/usr/bin/env bash
# sidekick.sh — bring-up/tear-down for falcosidekick stack
# Handles snap Docker's AppArmor stuck-container problem automatically.
#
# Usage:
#   ./sidekick.sh up
#   ./sidekick.sh down
#   ./sidekick.sh restart

COMPOSE_FILE="$(cd "$(dirname "$0")" && pwd)/docker-compose.falcosidekick.yaml"
CONTAINERS=(falcosidekick falcosidekick-ui falcosidekick-ui-redis)

# Kill all processes in a container's cgroup, works even when AppArmor
# blocks Docker from sending signals (the snap Docker problem).
cgroup_kill() {
    local id="$1"
    local scope="/sys/fs/cgroup/system.slice/docker-${id}.scope"
    if [ -f "${scope}/cgroup.kill" ]; then
        echo 1 | sudo tee "${scope}/cgroup.kill" >/dev/null 2>&1 && return 0
    fi
    # Fallback: kill shim init.pid
    local task_dir="/run/snap.docker/containerd/daemon/io.containerd.runtime.v2.task/moby/${id}"
    local pid_file="${task_dir}/init.pid"
    if [ -f "$pid_file" ]; then
        sudo kill -9 "$(cat "$pid_file")" 2>/dev/null || true
        sudo rm -rf "$task_dir" 2>/dev/null || true
    fi
}

force_remove() {
    local name="$1"
    local id
    id=$(docker ps -aq --filter "name=^${name}$" 2>/dev/null | head -1)
    [ -z "$id" ] && return 0
    echo "  Force-removing $name ($id)..."
    cgroup_kill "$id"
    sleep 1
    docker rm -f "$name" 2>/dev/null || true
}

kill_port() {
    local port="$1"
    local pid
    pid=$(sudo lsof -i :"$port" -n -P 2>/dev/null | awk 'NR==2{print $2}')
    if [ -n "$pid" ]; then
        # Try cgroup kill first (AppArmor-safe)
        local cgroup
        cgroup=$(awk -F: '/^0::/{print $3}' /proc/"$pid"/cgroup 2>/dev/null)
        if [ -n "$cgroup" ] && [ -f "/sys/fs/cgroup${cgroup}/cgroup.kill" ]; then
            echo 1 | sudo tee "/sys/fs/cgroup${cgroup}/cgroup.kill" >/dev/null 2>&1
        else
            sudo kill -9 "$pid" 2>/dev/null || true
        fi
        echo "  Killed process on port $port (PID $pid)"
    fi
}

cmd_down() {
    echo "==> Bringing down falcosidekick stack..."
    docker compose -f "$COMPOSE_FILE" down --timeout 5 2>/dev/null || true

    # Force-remove any containers still present
    for name in "${CONTAINERS[@]}"; do
        if docker ps -aq --filter "name=^${name}$" | grep -q .; then
            force_remove "$name"
        fi
    done

    # Kill any ghost processes holding the ports
    for port in 6379 2801 2802; do
        if sudo lsof -i :"$port" -n -P 2>/dev/null | grep -q LISTEN; then
            kill_port "$port"
        fi
    done

    sleep 1
    echo "==> Stack is down."
}

cmd_up() {
    echo "==> Starting falcosidekick stack..."
    cd "$(dirname "$COMPOSE_FILE")"
    docker compose -f "$COMPOSE_FILE" up -d
    echo ""
    echo "  Falcosidekick:    http://localhost:2801"
    echo "  Falcosidekick UI: http://localhost:2802/ui"
    echo ""
    echo "  Start Falco with:"
    echo "    sudo falco ... -o http_output.enabled=true -o http_output.url=http://localhost:2801"
}

case "${1:-}" in
    up)      cmd_up ;;
    down)    cmd_down ;;
    restart) cmd_down; sleep 1; cmd_up ;;
    *)
        echo "Usage: $0 {up|down|restart}"
        exit 1
        ;;
esac
