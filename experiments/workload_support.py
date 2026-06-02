#!/usr/bin/env python3
"""Shared helpers for workload-enabled experiment batches."""

from __future__ import annotations

import json
import logging
import math
import os
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Optional


ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "results"
WORKLOAD_DIR = ROOT / "workload"
WORKLOAD_COMPOSE = ROOT / "docker-compose.workload.yaml"

DEFAULT_WORKLOAD_STABILIZE_SEC = 30
DEFAULT_WORKLOAD_MONITOR_INTERVAL = 1
DEFAULT_PRE_CAPTURE_SEC = 5
PROCESS_STOP_TIMEOUT = 10


@dataclass
class WorkloadSession:
    """Tracks the helper processes and files for a workload-backed batch."""

    batch_label: str
    resource_csv: Path
    drive_proc: Optional[subprocess.Popen] = None
    monitor_proc: Optional[subprocess.Popen] = None
    active: bool = False
    stabilize_sec: int = DEFAULT_WORKLOAD_STABILIZE_SEC
    pre_capture_sec: int = DEFAULT_PRE_CAPTURE_SEC


def batch_label(outstamp: str, workload_enabled: bool) -> str:
    """Return the directory/file label for a batch."""
    return f"{outstamp}_workload" if workload_enabled else outstamp


def percentile(values: Iterable[float], pct: float) -> Optional[float]:
    """Compute a percentile with linear interpolation."""
    ordered = sorted(float(v) for v in values)
    if not ordered:
        return None
    if len(ordered) == 1:
        return ordered[0]

    rank = (len(ordered) - 1) * (pct / 100.0)
    low = math.floor(rank)
    high = math.ceil(rank)
    if low == high:
        return ordered[int(rank)]
    weight = rank - low
    return ordered[low] + (ordered[high] - ordered[low]) * weight


def json_dumps(value) -> str:
    """Stable JSON encoding for CSV columns."""
    return json.dumps(value, sort_keys=True)


def summarize_events(
    events,
    layer1_rules,
    layer2_rules,
    *,
    workload_active: bool,
    attack_offset_ms: int = 0,
) -> Dict:
    """Build per-run metrics used by both harnesses and the figure generator."""
    rule_counts: Dict[str, int] = {}
    layer1_events = []
    layer2_events = []

    for evt in events:
        rule = evt.get("rule")
        if not rule:
            continue
        rule_counts[rule] = rule_counts.get(rule, 0) + 1
        if rule in layer1_rules:
            layer1_events.append(evt)
        if rule in layer2_rules:
            layer2_events.append(evt)

    first_latency_ms = min(
        (
            evt.get("_latency_ms")
            for evt in events
            if evt.get("_latency_ms") is not None and evt.get("_latency_ms") >= 0
        ),
        default=None,
    )
    layer2_latencies_ms = sorted(
        int(evt["_latency_ms"])
        for evt in layer2_events
        if evt.get("_latency_ms") is not None and evt.get("_latency_ms") >= 0
    )
    event_offsets_ms = sorted(
        int(evt.get("_capture_offset_ms", evt.get("_latency_ms", 0)))
        for evt in events
        if evt.get("_capture_offset_ms") is not None or evt.get("_latency_ms") is not None
    )

    total_events = len(events)
    layer2_count = len(layer2_events)

    return {
        "workload_active": bool(workload_active),
        "attack_offset_ms": int(attack_offset_ms),
        "total_events": total_events,
        "layer1_count": len(layer1_events),
        "layer2_count": layer2_count,
        "noise_events": max(0, total_events - layer2_count),
        "snr": (layer2_count / total_events) if total_events else 0.0,
        "rules_fired": sorted(rule_counts),
        "rule_counts": rule_counts,
        "layer2_rules_fired": sorted({evt["rule"] for evt in layer2_events}),
        "first_latency_ms": first_latency_ms,
        "first_layer2_latency_ms": layer2_latencies_ms[0] if layer2_latencies_ms else None,
        "latencies_ms": layer2_latencies_ms,
        "median_latency_ms": percentile(layer2_latencies_ms, 50),
        "p95_latency_ms": percentile(layer2_latencies_ms, 95),
        "p99_latency_ms": percentile(layer2_latencies_ms, 99),
        "event_offsets_ms": event_offsets_ms,
    }


def _ensure_assets_exist() -> None:
    required = [
        WORKLOAD_COMPOSE,
        WORKLOAD_DIR / "drive_load.sh",
        WORKLOAD_DIR / "monitor_resources.sh",
    ]
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        raise FileNotFoundError(f"Missing workload assets: {missing}")


def _terminate_process(proc: Optional[subprocess.Popen], logger: logging.Logger, label: str) -> None:
    if proc is None:
        return

    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        proc.wait(timeout=PROCESS_STOP_TIMEOUT)
        logger.debug("Stopped %s (pid=%s)", label, proc.pid)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            proc.wait(timeout=2)
            logger.warning("Force killed %s (pid=%s)", label, proc.pid)
        except Exception as exc:  # pragma: no cover - defensive cleanup
            logger.warning("Failed to kill %s: %s", label, exc)
    except Exception as exc:  # pragma: no cover - defensive cleanup
        logger.warning("Failed to stop %s: %s", label, exc)


def _update_resource_symlink(resource_csv: Path) -> None:
    link = DATA_DIR / "resource_usage_workload_latest.csv"
    if link.exists() or link.is_symlink():
        link.unlink()
    link.symlink_to(resource_csv.name)


def start_workload(
    outstamp: str,
    logger: logging.Logger,
    *,
    stabilize_sec: int = DEFAULT_WORKLOAD_STABILIZE_SEC,
    monitor_interval: int = DEFAULT_WORKLOAD_MONITOR_INTERVAL,
    pre_capture_sec: int = DEFAULT_PRE_CAPTURE_SEC,
) -> WorkloadSession:
    """Bring up the workload stack and start background load + monitoring."""
    _ensure_assets_exist()

    label = batch_label(outstamp, True)
    resource_csv = DATA_DIR / f"resource_usage_{label}.csv"
    resource_csv.parent.mkdir(parents=True, exist_ok=True)

    logger.info("Starting workload stack via %s", WORKLOAD_COMPOSE.name)
    subprocess.run(
        ["docker", "compose", "-f", str(WORKLOAD_COMPOSE), "up", "-d"],
        check=True,
        capture_output=True,
        text=True,
    )

    logger.info("Waiting %ss for workload containers to stabilize", stabilize_sec)
    time.sleep(stabilize_sec)

    drive_proc = subprocess.Popen(
        ["bash", str(WORKLOAD_DIR / "drive_load.sh"), "0"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid,
    )
    monitor_proc = subprocess.Popen(
        [
            "bash",
            str(WORKLOAD_DIR / "monitor_resources.sh"),
            str(resource_csv),
            str(monitor_interval),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid,
    )

    _update_resource_symlink(resource_csv)

    return WorkloadSession(
        batch_label=label,
        resource_csv=resource_csv,
        drive_proc=drive_proc,
        monitor_proc=monitor_proc,
        active=True,
        stabilize_sec=stabilize_sec,
        pre_capture_sec=pre_capture_sec,
    )


def stop_workload(session: Optional[WorkloadSession], logger: logging.Logger) -> None:
    """Stop background helpers and tear down workload containers."""
    if session is None or not session.active:
        return

    _terminate_process(session.drive_proc, logger, "workload driver")
    _terminate_process(session.monitor_proc, logger, "resource monitor")

    try:
        subprocess.run(
            ["docker", "compose", "-f", str(WORKLOAD_COMPOSE), "down"],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        logger.warning("Failed to stop workload stack cleanly: %s", exc.stderr.strip())

    session.active = False
