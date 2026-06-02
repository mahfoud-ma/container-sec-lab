#!/usr/bin/env python3
"""Phase 2 evasion experiment runner."""

import argparse
import csv
import json
import logging
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from workload_support import WorkloadSession, batch_label, start_workload, stop_workload, summarize_events

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parents[1]
SCEN_DIR = ROOT / "scenarios"
EVASION_DIR = SCEN_DIR / "evasion"
DATA_DIR = ROOT / "results"
OUT_DIR = DATA_DIR / "evasion_runs"
OUT_DIR.mkdir(parents=True, exist_ok=True)

FALCO_DEFAULT_RULES = [
    "/etc/falco/falco_rules.yaml",
    "/etc/falco/falco_rules.local.yaml",
]
CUSTOM_RULES_DIR = ROOT / "falco" / "rules.d"
CUSTOM_RULES = sorted(str(p) for p in CUSTOM_RULES_DIR.glob("*.yaml"))

LAYER2_RULES = {
    "Container Docker Socket Access",
    "Container Calling setns Syscall",
    "Container Calling unshare Syscall",
    "Container Using nsenter",
    "Container Unix Socket Connection",
    "Container Writing Under Mounted Host Root",
    "Container With Docker Socket Mounted",
    "Container With Host Root Mounted",
}

LAYER1_RULES = {
    "Container Process Spawned",
    "Container File Activity",
    "Container Network Connection",
    "Container Reading Sensitive Paths",
    "Container Using System Tools",
}

ALL_CUSTOM_RULES = LAYER1_RULES | LAYER2_RULES

EVASION_EXPERIMENTS = {
    "E1_rename": {
        "script": "e1_binary_rename.sh",
        "target_scenario": "S2",
        "evasion_technique": "Binary renaming to alternate helper path (/tmp/join_host)",
        "evasion_level": 1,
        "description": "Execute the same helper from an alternate path without exposing the original name in container cmdlines",
        "key_rules": ["Container Calling setns Syscall", "Container Using nsenter"],
    },
    "E1b_custom_c": {
        "script": "e1b_custom_setns.sh",
        "target_scenario": "S2",
        "evasion_technique": "Custom C binary calling setns() directly",
        "evasion_level": 2,
        "description": "Custom compiled binary that calls setns() without nsenter",
        "key_rules": ["Container Calling setns Syscall", "Container Using nsenter"],
    },
    "E2_unshare": {
        "script": "e2_unshare.sh",
        "target_scenario": "S2",
        "evasion_technique": "unshare instead of nsenter (different syscall)",
        "evasion_level": 3,
        "description": "Uses unshare() syscall instead of setns()",
        "key_rules": ["Container Calling setns Syscall", "Container Using nsenter", "Container Calling unshare Syscall"],
    },
    "E3a_symlink": {
        "script": "e3a_symlink_only.sh",
        "target_scenario": "S1",
        "evasion_technique": "Symlink to docker.sock (cat /tmp/sock-link)",
        "evasion_level": 1,
        "description": "Access docker.sock via symlink indirection only",
        "key_rules": ["Container Docker Socket Access", "Container Unix Socket Connection", "Container With Docker Socket Mounted"],
    },
    "E3b_fd_redirect": {
        "script": "e3b_fd_redirect_only.sh",
        "target_scenario": "S1",
        "evasion_technique": "FD redirect via aliased mount path (/tmp/s -> /dev/fd/3)",
        "evasion_level": 1,
        "description": "Open the mounted socket through an alternate path, then read through /dev/fd/3",
        "key_rules": ["Container Docker Socket Access", "Container Unix Socket Connection", "Container With Docker Socket Mounted"],
    },
    "E4_symlink_mount": {
        "script": "e4_symlink_hostmount.sh",
        "target_scenario": "S3",
        "evasion_technique": "Symlink to mounted host path",
        "evasion_level": 1,
        "description": "Write to host mount through symlink indirection",
        "key_rules": ["Container Writing Under Mounted Host Root", "Container With Host Root Mounted"],
    },
}

E6_SCRIPT = "e6_startup_timing.sh"
E6_ITERATIONS = 10

E5_SCRIPT = "e5_false_positive.sh"
E5_DURATION = 300

FALCO_START_TIMEOUT = 10
FALCO_STOP_TIMEOUT = 10


def parse_evt_time_iso8601_to_ns(ts: str) -> int:
    """Parse Falco 'time' field to epoch nanoseconds."""
    s = ts.strip()
    z = s.endswith("Z")
    if z:
        s = s[:-1]
    frac_ns = 0
    if "." in s:
        head, frac = s.split(".", 1)
        tz_sign_pos = max(frac.find("+"), frac.find("-"))
        if tz_sign_pos != -1:
            frac_part = frac[:tz_sign_pos]
            tz_part = frac[tz_sign_pos:]
            s_no_frac = f"{head}{tz_part}"
        else:
            frac_part = frac
            s_no_frac = head
        frac_digits = ''.join(ch for ch in frac_part if ch.isdigit())
        frac_digits = frac_digits[:9].ljust(9, "0")
        try:
            frac_ns = int(frac_digits)
        except ValueError:
            frac_ns = 0
        base_str = s_no_frac
    else:
        base_str = s

    if z and not base_str.endswith("Z"):
        base_str += "Z"

    try:
        if base_str.endswith("Z"):
            base_dt = datetime.fromisoformat(base_str[:-1]).replace(tzinfo=timezone.utc)
        else:
            base_dt = datetime.fromisoformat(base_str)
            if base_dt.tzinfo is None:
                base_dt = base_dt.replace(tzinfo=timezone.utc)
    except Exception:
        base_dt = datetime.now(timezone.utc)

    return int(base_dt.timestamp()) * 1_000_000_000 + frac_ns


def start_falco(logfile: Path) -> Optional[subprocess.Popen]:
    """Start Falco with all custom rules, outputting to logfile."""
    try:
        subprocess.run(["sudo", "pkill", "-9", "falco"], capture_output=True, timeout=5)
        time.sleep(0.5)
    except Exception:
        pass

    import tempfile
    temp_fd, temp_logfile = tempfile.mkstemp(suffix='.jsonl', prefix='falco_evasion_')
    os.close(temp_fd)
    os.chmod(temp_logfile, 0o666)

    args = [
        "sudo", "falco",
        "-o", "json_output=true",
        "-o", "time_format_iso_8601=true",
        "-o", f"file_output.enabled=true",
        "-o", f"file_output.filename={temp_logfile}",
        "-o", "file_output.keep_alive=false",
        "-o", "stdout_output.enabled=false",
        "-o", "syslog_output.enabled=false",
        "-o", "buffered_outputs=false",
        "-o", "syscall_event_drops.actions=ignore",
        "-o", "syscall_event_drops.threshold=0.1",
        "-o", "grpc.enabled=false",
        "-o", "webserver.enabled=false",
        "-o", "http_output.enabled=false",
        "-o", "rule_matching=all",
    ]

    for rule_file in FALCO_DEFAULT_RULES:
        if Path(rule_file).exists():
            args.extend(["-r", rule_file])
    for rule_file in CUSTOM_RULES:
        args.extend(["-r", rule_file])

    try:
        proc = subprocess.Popen(
            args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid,
        )
        proc._temp_logfile = temp_logfile
        proc._final_logfile = logfile

        time.sleep(1)
        if proc.poll() is not None:
            logger.error("Falco failed to start")
            return None

        logger.debug(f"Falco started (PID: {proc.pid})")
        return proc
    except Exception as e:
        logger.error(f"Failed to start Falco: {e}")
        return None


def stop_falco(proc: subprocess.Popen) -> None:
    """Stop Falco and copy temp logfile to final location."""
    if proc is None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        proc.wait(timeout=FALCO_STOP_TIMEOUT)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            proc.wait(timeout=2)
        except Exception:
            pass
    except Exception:
        pass

    if hasattr(proc, '_temp_logfile') and hasattr(proc, '_final_logfile'):
        try:
            import shutil
            if os.path.exists(proc._temp_logfile):
                shutil.copy2(proc._temp_logfile, proc._final_logfile)
                os.remove(proc._temp_logfile)
        except Exception as e:
            logger.warning(f"Failed to copy log: {e}")


def warm_up_falco(seconds: int = 3) -> None:
    """Warm up Falco with dummy container."""
    time.sleep(seconds)
    try:
        subprocess.run(
            ["docker", "run", "--rm", "alpine:latest", "echo", "warmup"],
            capture_output=True, timeout=10,
        )
    except Exception:
        pass
    time.sleep(1)


def parse_falco_events(logfile: Path, t0_ns: int, capture_t0_ns: Optional[int] = None) -> List[Dict]:
    """Parse Falco JSONL output."""
    events = []
    if not logfile.exists():
        return events

    time.sleep(0.5)
    with logfile.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                evt = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "time" not in evt or "rule" not in evt:
                continue

            of = evt.get("output_fields", {}) or {}
            evt_time_field = of.get("evt.time")
            if isinstance(evt_time_field, (int, float)):
                evt_ns = int(evt_time_field)
            else:
                evt_ns = parse_evt_time_iso8601_to_ns(evt["time"])

            evt["_latency_ms"] = (evt_ns - t0_ns) // 1_000_000
            evt["_capture_offset_ms"] = (evt_ns - (capture_t0_ns or t0_ns)) // 1_000_000
            events.append(evt)

    return events


def run_single_evasion(
    exp_id: str,
    script_path: Path,
    run_dir: Path,
    run_num: int,
    warmup_sec: int = 3,
    workload_session: Optional[WorkloadSession] = None,
) -> Dict:
    """Run one evasion experiment iteration."""
    logfile = run_dir / f"{exp_id}_run{run_num:02d}.jsonl"
    if logfile.exists():
        logfile.unlink()

    falco = start_falco(logfile)
    if falco is None:
        return {"experiment": exp_id, "run_num": run_num, "error": "Falco failed to start",
                "rules_fired": [], "layer1_count": 0, "layer2_count": 0, "total_events": 0}

    time.sleep(max(2, warmup_sec))
    warm_up_falco(warmup_sec)

    pre_capture_sec = workload_session.pre_capture_sec if workload_session and workload_session.active else 0
    capture_t0_ns = time.time_ns()
    if pre_capture_sec > 0:
        time.sleep(pre_capture_sec)
    t0_ns = time.time_ns()

    try:
        result = subprocess.run(
            ["bash", str(script_path)],
            capture_output=True, text=True, timeout=120,
        )
        scen_rc = result.returncode
    except subprocess.TimeoutExpired:
        scen_rc = 124
    except Exception as e:
        scen_rc = 1

    time.sleep(3)
    stop_falco(falco)
    time.sleep(0.5)

    events = parse_falco_events(logfile, t0_ns, capture_t0_ns)
    metrics = summarize_events(
        events,
        LAYER1_RULES,
        LAYER2_RULES,
        workload_active=bool(workload_session and workload_session.active),
        attack_offset_ms=pre_capture_sec * 1000,
    )

    result_dict = {
        "experiment": exp_id,
        "run_num": run_num,
        "scen_rc": scen_rc,
        "logfile": str(logfile),
        "capture_pre_window_sec": pre_capture_sec,
    }
    result_dict.update(metrics)
    if workload_session and workload_session.active:
        result_dict["resource_csv"] = str(workload_session.resource_csv)
    return result_dict


def run_evasion_experiments(
    outstamp: str,
    runs: int,
    warmup: int,
    workload_session: Optional[WorkloadSession] = None,
) -> List[Dict]:
    """Run all evasion experiments E1-E4."""
    results = []
    run_dir = OUT_DIR / batch_label(outstamp, bool(workload_session and workload_session.active)) / "evasion"
    run_dir.mkdir(parents=True, exist_ok=True)

    total = len(EVASION_EXPERIMENTS) * runs
    current = 0

    for exp_id, meta in EVASION_EXPERIMENTS.items():
        script = EVASION_DIR / meta["script"]
        if not script.exists():
            logger.error(f"Script not found: {script}")
            continue

        logger.info(f"\n--- {exp_id}: {meta['evasion_technique']} ---")
        logger.info(f"    Target: {meta['target_scenario']} | Level: {meta['evasion_level']}")

        for run_num in range(1, runs + 1):
            current += 1
            logger.info(f"  [{current}/{total}] Run {run_num}/{runs}")

            result = run_single_evasion(
                exp_id,
                script,
                run_dir,
                run_num,
                warmup,
                workload_session,
            )
            result.update({
                "target_scenario": meta["target_scenario"],
                "evasion_technique": meta["evasion_technique"],
                "evasion_level": meta["evasion_level"],
                "key_rules": meta["key_rules"],
            })
            results.append(result)

            key_fired = [r for r in meta["key_rules"] if r in result.get("rules_fired", [])]
            key_missed = [r for r in meta["key_rules"] if r not in result.get("rules_fired", [])]
            if key_fired:
                logger.info(f"    FIRED: {key_fired}")
            if key_missed:
                logger.info(f"    MISSED: {key_missed}")
            logger.info(
                "    Total events: %s (L1=%s, L2=%s, noise=%s, SNR=%.4f)",
                result["total_events"],
                result["layer1_count"],
                result["layer2_count"],
                result["noise_events"],
                result["snr"],
            )

    return results


def run_e6_startup_timing(
    outstamp: str,
    iterations: int,
    warmup: int,
    workload_session: Optional[WorkloadSession] = None,
) -> List[Dict]:
    """Run E6 startup timing test multiple times."""
    results = []
    run_dir = OUT_DIR / batch_label(outstamp, bool(workload_session and workload_session.active)) / "e6_startup"
    run_dir.mkdir(parents=True, exist_ok=True)

    script = EVASION_DIR / E6_SCRIPT
    if not script.exists():
        logger.error(f"E6 script not found: {script}")
        return results

    logger.info(f"\n=== E6: Startup Timing Quantification ({iterations} iterations) ===")

    for i in range(1, iterations + 1):
        logger.info(f"  [{i}/{iterations}] Startup timing test")
        result = run_single_evasion("E6_startup", script, run_dir, i, warmup, workload_session)
        result.update({
            "target_scenario": "S1",
            "evasion_technique": "eBPF startup timing exploitation",
            "evasion_level": 0,
            "key_rules": ["Container Docker Socket Access"],
        })
        results.append(result)

        has_l2 = "Container Docker Socket Access" in result.get("rules_fired", [])
        status = "DETECTED" if has_l2 else "MISSED (startup window)"
        logger.info(f"    Docker Socket Access: {status} | Events: {result['total_events']}")

    detected = sum(1 for r in results if "Container Docker Socket Access" in r.get("rules_fired", []))
    logger.info(f"\n  E6 Summary: {detected}/{iterations} detected ({detected/iterations*100:.0f}%)")
    logger.info(f"  Startup window miss rate: {iterations - detected}/{iterations} ({(iterations-detected)/iterations*100:.0f}%)")

    return results


def run_e5_false_positive(
    outstamp: str,
    duration: int,
    warmup: int,
    workload_session: Optional[WorkloadSession] = None,
) -> Dict:
    """Run E5 false positive baseline test."""
    run_dir = OUT_DIR / batch_label(outstamp, bool(workload_session and workload_session.active)) / "e5_fp"
    run_dir.mkdir(parents=True, exist_ok=True)
    logfile = run_dir / "e5_false_positive.jsonl"

    script = EVASION_DIR / E5_SCRIPT
    if not script.exists():
        logger.error(f"E5 script not found: {script}")
        return {}

    logger.info(f"\n=== E5: False Positive Baseline ({duration}s) ===")

    if logfile.exists():
        logfile.unlink()

    falco = start_falco(logfile)
    if falco is None:
        return {"error": "Falco failed to start"}

    time.sleep(max(2, warmup))
    warm_up_falco(warmup)

    pre_capture_sec = workload_session.pre_capture_sec if workload_session and workload_session.active else 0
    capture_t0_ns = time.time_ns()
    if pre_capture_sec > 0:
        time.sleep(pre_capture_sec)
    t0_ns = time.time_ns()

    try:
        result = subprocess.run(
            ["bash", str(script), str(duration)],
            capture_output=True, text=True, timeout=duration + 60,
        )
    except subprocess.TimeoutExpired:
        logger.warning("E5 timed out")
    except Exception as e:
        logger.error(f"E5 error: {e}")

    time.sleep(5)
    stop_falco(falco)
    time.sleep(1)

    events = parse_falco_events(logfile, t0_ns, capture_t0_ns)
    metrics = summarize_events(
        events,
        LAYER1_RULES,
        LAYER2_RULES,
        workload_active=bool(workload_session and workload_session.active),
        attack_offset_ms=pre_capture_sec * 1000,
    )

    rule_counts = {}
    for e in events:
        rule = e["rule"]
        rule_counts[rule] = rule_counts.get(rule, 0) + 1

    layer1_events = {r: c for r, c in rule_counts.items() if r in LAYER1_RULES}
    layer2_events = {r: c for r, c in rule_counts.items() if r in LAYER2_RULES}
    other_events = {r: c for r, c in rule_counts.items() if r not in ALL_CUSTOM_RULES}

    duration_min = duration / 60.0

    logger.info(f"\n  E5 Results ({duration}s = {duration_min:.1f} min):")
    logger.info(f"  Total events: {len(events)}")
    logger.info(f"\n  Layer 1 (broad activity):")
    for rule, count in sorted(layer1_events.items()):
        logger.info(f"    {rule}: {count} events ({count/duration_min:.1f}/min)")
    logger.info(f"\n  Layer 2 (escape-specific):")
    if layer2_events:
        for rule, count in sorted(layer2_events.items()):
            logger.info(f"    {rule}: {count} events ({count/duration_min:.1f}/min) *** FALSE POSITIVE ***")
    else:
        logger.info(f"    (none) -- Layer 2 is clean")
    if other_events:
        logger.info(f"\n  Other (default Falco rules):")
        for rule, count in sorted(other_events.items()):
            logger.info(f"    {rule}: {count}")

    return {
        "duration_sec": duration,
        "capture_pre_window_sec": pre_capture_sec,
        "resource_csv": str(workload_session.resource_csv) if workload_session and workload_session.active else None,
        "total_events": len(events),
        "layer1_events": layer1_events,
        "layer2_events": layer2_events,
        "other_events": other_events,
        "events_per_min": len(events) / duration_min if duration_min > 0 else 0,
        "layer1_per_min": sum(layer1_events.values()) / duration_min if duration_min > 0 else 0,
        "layer2_per_min": sum(layer2_events.values()) / duration_min if duration_min > 0 else 0,
        "logfile": str(logfile),
        "workload_active": bool(workload_session and workload_session.active),
        "noise_events": metrics["noise_events"],
        "snr": metrics["snr"],
        "latencies_ms": metrics["latencies_ms"],
        "median_latency_ms": metrics["median_latency_ms"],
        "p95_latency_ms": metrics["p95_latency_ms"],
        "p99_latency_ms": metrics["p99_latency_ms"],
        "event_offsets_ms": metrics["event_offsets_ms"],
        "rule_counts": metrics["rule_counts"],
    }


def generate_evasion_matrix(evasion_results: List[Dict], e6_results: List[Dict]) -> Dict:
    """Generate the evasion results matrix: scenario x technique with rule detection."""
    matrix = {}

    for r in evasion_results:
        exp = r["experiment"]
        if exp not in matrix:
            matrix[exp] = {
                "target_scenario": r["target_scenario"],
                "evasion_technique": r["evasion_technique"],
                "evasion_level": r["evasion_level"],
                "runs": [],
            }
        matrix[exp]["runs"].append({
            "run_num": r["run_num"],
            "rules_fired": r.get("rules_fired", []),
            "layer2_rules_fired": r.get("layer2_rules_fired", []),
            "total_events": r["total_events"],
            "layer1_count": r["layer1_count"],
            "layer2_count": r["layer2_count"],
            "noise_events": r.get("noise_events", 0),
            "snr": r.get("snr", 0.0),
            "first_layer2_latency_ms": r.get("first_layer2_latency_ms"),
        })

    if e6_results:
        matrix["E6_startup"] = {
            "target_scenario": "S1",
            "evasion_technique": "eBPF startup timing exploitation",
            "evasion_level": 0,
            "runs": [{
                "run_num": r["run_num"],
                "rules_fired": r.get("rules_fired", []),
                "layer2_rules_fired": r.get("layer2_rules_fired", []),
                "total_events": r["total_events"],
                "layer1_count": r["layer1_count"],
                "layer2_count": r["layer2_count"],
                "noise_events": r.get("noise_events", 0),
                "snr": r.get("snr", 0.0),
                "first_layer2_latency_ms": r.get("first_layer2_latency_ms"),
            } for r in e6_results],
        }

    summary = {}
    for exp_id, data in matrix.items():
        n_runs = len(data["runs"])
        key_rules = EVASION_EXPERIMENTS.get(exp_id, {}).get("key_rules", [])
        if exp_id == "E6_startup":
            key_rules = ["Container Docker Socket Access"]

        rule_rates = {}
        for rule in key_rules:
            fired = sum(1 for run in data["runs"] if rule in run.get("rules_fired", []))
            rule_rates[rule] = f"{fired}/{n_runs}"

        summary[exp_id] = {
            "target_scenario": data["target_scenario"],
            "evasion_technique": data["evasion_technique"],
            "evasion_level": data["evasion_level"],
            "num_runs": n_runs,
            "rule_detection_rates": rule_rates,
            "avg_total_events": sum(r["total_events"] for r in data["runs"]) / n_runs,
            "avg_noise_events": sum(r.get("noise_events", 0) for r in data["runs"]) / n_runs,
            "avg_layer2_events": sum(r["layer2_count"] for r in data["runs"]) / n_runs,
            "avg_snr": sum(r.get("snr", 0.0) for r in data["runs"]) / n_runs,
        }

    return summary


def save_results(
    outstamp: str,
    evasion_results: List[Dict],
    e6_results: List[Dict],
    e5_result: Dict,
    matrix_summary: Dict,
    *,
    workload_enabled: bool,
    workload_session: Optional[WorkloadSession],
) -> None:
    label = batch_label(outstamp, workload_enabled)
    results_file = DATA_DIR / f"evasion_results_{label}.json"
    output = {
        "timestamp": outstamp,
        "batch_label": label,
        "falco_version": "0.43.0",
        "driver": "modern_ebpf",
        "workload_active": workload_enabled,
        "resource_csv": str(workload_session.resource_csv) if workload_session else None,
        "evasion_experiments": evasion_results,
        "e6_startup_timing": e6_results,
        "e5_false_positive": e5_result,
        "matrix_summary": matrix_summary,
    }

    with results_file.open("w") as f:
        json.dump(output, f, indent=2, default=str)
    logger.info(f"\nResults saved: {results_file}")

    summary_file = DATA_DIR / f"evasion_summary_{label}.txt"
    with summary_file.open("w") as f:
        f.write(f"Phase 2 Evasion Experiment Results — {label}\n")
        f.write("=" * 70 + "\n\n")
        if workload_enabled:
            f.write(f"Workload mode: enabled\nResource CSV: {workload_session.resource_csv}\n\n")

        f.write("EVASION MATRIX (Scenario x Technique -> Rule Detection Rate)\n")
        f.write("-" * 70 + "\n\n")

        for exp_id, data in sorted(matrix_summary.items(), key=lambda x: (x[1]["target_scenario"], x[1]["evasion_level"])):
            f.write(f"{exp_id} [{data['target_scenario']}] (Level {data['evasion_level']})\n")
            f.write(f"  Technique: {data['evasion_technique']}\n")
            f.write(
                f"  Runs: {data['num_runs']} | Avg events: {data['avg_total_events']:.1f} | "
                f"Avg noise: {data['avg_noise_events']:.1f} | Avg L2: {data['avg_layer2_events']:.1f} | "
                f"Avg SNR: {data['avg_snr']:.4f}\n"
            )
            for rule, rate in data["rule_detection_rates"].items():
                f.write(f"  {rule}: {rate}\n")
            f.write("\n")

        if e5_result and "total_events" in e5_result:
            f.write("\nFALSE POSITIVE BASELINE (E5)\n")
            f.write("-" * 70 + "\n")
            f.write(f"Duration: {e5_result['duration_sec']}s\n")
            f.write(f"Total events: {e5_result['total_events']} ({e5_result['events_per_min']:.1f}/min)\n")
            f.write(f"Layer 1: {e5_result['layer1_per_min']:.1f}/min\n")
            f.write(f"Layer 2: {e5_result['layer2_per_min']:.1f}/min\n")
            if e5_result.get("layer1_events"):
                f.write("\nLayer 1 breakdown:\n")
                for rule, count in sorted(e5_result["layer1_events"].items()):
                    f.write(f"  {rule}: {count}\n")
            if e5_result.get("layer2_events"):
                f.write("\n*** Layer 2 FALSE POSITIVES: ***\n")
                for rule, count in sorted(e5_result["layer2_events"].items()):
                    f.write(f"  {rule}: {count}\n")
            else:
                f.write("\nLayer 2: CLEAN (0 false positives)\n")

    logger.info(f"Summary saved: {summary_file}")

    csv_file = DATA_DIR / f"evasion_csv_{label}.csv"
    all_rules = sorted(ALL_CUSTOM_RULES)
    fieldnames = [
        "experiment", "target_scenario", "evasion_technique", "evasion_level",
        "runs", "workload_active", "l2_detection_rate", "avg_total_events", "avg_l1_events",
        "avg_l2_events", "noise_events", "snr", "first_layer2_latency_ms",
        "median_latency_ms", "p95_latency_ms", "p99_latency_ms",
    ] + all_rules

    csv_rows = []

    for r in evasion_results:
        exp = r["experiment"]
        run_num = r["run_num"]
        rule_fired = {rule: 1 if rule in r.get("rules_fired", []) else 0
                      for rule in all_rules}
        csv_rows.append({
            "experiment": exp,
            "target_scenario": r.get("target_scenario", ""),
            "evasion_technique": r.get("evasion_technique", ""),
            "evasion_level": r.get("evasion_level", ""),
            "runs": f"run{run_num:02d}",
            "workload_active": int(r.get("workload_active", False)),
            "l2_detection_rate": "",
            "avg_total_events": r.get("total_events", 0),
            "avg_l1_events": r.get("layer1_count", 0),
            "avg_l2_events": r.get("layer2_count", 0),
            "noise_events": r.get("noise_events", 0),
            "snr": f"{r.get('snr', 0.0):.6f}",
            "first_layer2_latency_ms": r.get("first_layer2_latency_ms", ""),
            "median_latency_ms": r.get("median_latency_ms", ""),
            "p95_latency_ms": r.get("p95_latency_ms", ""),
            "p99_latency_ms": r.get("p99_latency_ms", ""),
            **rule_fired,
        })

    for r in e6_results:
        run_num = r["run_num"]
        rule_fired = {rule: 1 if rule in r.get("rules_fired", []) else 0
                      for rule in all_rules}
        csv_rows.append({
            "experiment": "E6_startup",
            "target_scenario": "S1",
            "evasion_technique": "eBPF startup timing",
            "evasion_level": 0,
            "runs": f"run{run_num:02d}",
            "workload_active": int(r.get("workload_active", False)),
            "l2_detection_rate": "",
            "avg_total_events": r.get("total_events", 0),
            "avg_l1_events": r.get("layer1_count", 0),
            "avg_l2_events": r.get("layer2_count", 0),
            "noise_events": r.get("noise_events", 0),
            "snr": f"{r.get('snr', 0.0):.6f}",
            "first_layer2_latency_ms": r.get("first_layer2_latency_ms", ""),
            "median_latency_ms": r.get("median_latency_ms", ""),
            "p95_latency_ms": r.get("p95_latency_ms", ""),
            "p99_latency_ms": r.get("p99_latency_ms", ""),
            **rule_fired,
        })

    for exp_id, data in sorted(matrix_summary.items()):
        rule_rates = {}
        for rule in all_rules:
            if exp_id == "E6_startup":
                exp_runs = e6_results
            else:
                exp_runs = [r for r in evasion_results if r["experiment"] == exp_id]
            fired = sum(1 for r in exp_runs if rule in r.get("rules_fired", []))
            n = len(exp_runs) if exp_runs else 1
            rule_rates[rule] = f"{fired}/{n}"

        l2_fired = sum(1 for r in (e6_results if exp_id == "E6_startup" else
                       [r for r in evasion_results if r["experiment"] == exp_id])
                       if any(rule in r.get("rules_fired", []) for rule in LAYER2_RULES))
        n = data["num_runs"]

        csv_rows.append({
            "experiment": f"{exp_id}_SUMMARY",
            "target_scenario": data["target_scenario"],
            "evasion_technique": data["evasion_technique"],
            "evasion_level": data["evasion_level"],
            "runs": n,
            "workload_active": int(workload_enabled),
            "l2_detection_rate": f"{l2_fired/n*100:.1f}%" if n else "N/A",
            "avg_total_events": f"{data['avg_total_events']:.1f}",
            "avg_l1_events": "",
            "avg_l2_events": f"{data['avg_layer2_events']:.1f}",
            "noise_events": f"{data['avg_noise_events']:.1f}",
            "snr": f"{data['avg_snr']:.6f}",
            "first_layer2_latency_ms": "",
            "median_latency_ms": "",
            "p95_latency_ms": "",
            "p99_latency_ms": "",
            **rule_rates,
        })

    with csv_file.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(csv_rows)
    logger.info(f"CSV summary saved: {csv_file}")

    for prefix in ("evasion_results", "evasion_summary", "evasion_csv"):
        ext = {"evasion_results": ".json", "evasion_summary": ".txt", "evasion_csv": ".csv"}[prefix]
        src = DATA_DIR / f"{prefix}_{label}{ext}"
        link_name = f"{prefix}_workload_latest{ext}" if workload_enabled else f"{prefix}_latest{ext}"
        link = DATA_DIR / link_name
        if link.exists() or link.is_symlink():
            link.unlink()
        link.symlink_to(src.name)


def main():
    global EVASION_EXPERIMENTS
    parser = argparse.ArgumentParser(
        description="Phase 2: Run evasion experiments against Falco custom rules",
    )
    parser.add_argument("--runs", type=int, default=5, help="Runs per evasion experiment")
    parser.add_argument("--e6-iterations", type=int, default=10, help="E6 startup timing iterations")
    parser.add_argument("--e5-duration", type=int, default=300, help="E5 false positive duration (seconds)")
    parser.add_argument("--warmup", type=int, default=3, help="Falco warmup seconds")
    parser.add_argument("--skip-e5", action="store_true", help="Skip E5 false positive test")
    parser.add_argument("--skip-e6", action="store_true", help="Skip E6 startup timing test")
    parser.add_argument("--only", type=str, help="Run only specific experiment (e.g., E1_rename)")
    parser.add_argument("--workload", action="store_true", help="Run with continuous background workload")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")

    args = parser.parse_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    logger.info("Validating environment...")
    try:
        subprocess.run(["which", "falco"], check=True, capture_output=True)
    except subprocess.CalledProcessError:
        logger.error("Falco not found in PATH")
        sys.exit(2)

    if not CUSTOM_RULES:
        logger.error("No custom rules found")
        sys.exit(2)

    logger.info(f"Custom rules: {len(CUSTOM_RULES)} files")

    outstamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    logger.info(f"Experiment batch: {batch_label(outstamp, args.workload)}")

    if args.only:
        filtered = {k: v for k, v in EVASION_EXPERIMENTS.items() if k == args.only}
        if not filtered:
            logger.error(f"Unknown experiment: {args.only}")
            sys.exit(1)
        orig = EVASION_EXPERIMENTS
        EVASION_EXPERIMENTS = filtered

    workload_session: Optional[WorkloadSession] = None
    try:
        if args.workload:
            workload_session = start_workload(outstamp, logger)

        evasion_results = run_evasion_experiments(outstamp, args.runs, args.warmup, workload_session)

        if args.only:
            EVASION_EXPERIMENTS = orig

        e6_results = []
        if not args.skip_e6:
            e6_results = run_e6_startup_timing(outstamp, args.e6_iterations, args.warmup, workload_session)

        e5_result = {}
        if not args.skip_e5:
            e5_result = run_e5_false_positive(outstamp, args.e5_duration, args.warmup, workload_session)

        matrix_summary = generate_evasion_matrix(evasion_results, e6_results)

        logger.info("\n" + "=" * 70)
        logger.info("EVASION RESULTS MATRIX")
        logger.info("=" * 70)
        for exp_id, data in sorted(matrix_summary.items(), key=lambda x: (x[1]["target_scenario"], x[1]["evasion_level"])):
            logger.info(f"\n{exp_id} [{data['target_scenario']}] Level {data['evasion_level']}")
            logger.info(f"  {data['evasion_technique']}")
            for rule, rate in data["rule_detection_rates"].items():
                logger.info(f"  -> {rule}: {rate}")

        save_results(
            outstamp,
            evasion_results,
            e6_results,
            e5_result,
            matrix_summary,
            workload_enabled=args.workload,
            workload_session=workload_session,
        )

        logger.info("\nPhase 2 experiments complete.")
    finally:
        if args.only:
            EVASION_EXPERIMENTS = orig
        stop_workload(workload_session, logger)


if __name__ == "__main__":
    main()
