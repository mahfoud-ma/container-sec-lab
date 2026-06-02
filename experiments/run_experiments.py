#!/usr/bin/env python3
"""Falco runtime security experiment runner."""

import argparse
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
import pandas as pd

from workload_support import WorkloadSession, batch_label, json_dumps, start_workload, stop_workload, summarize_events

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parents[1]
SCEN_DIR = ROOT / "scenarios"
DATA_DIR = ROOT / "results"
OUT_DIR = DATA_DIR / "runs"

OUT_DIR.mkdir(parents=True, exist_ok=True)

FALCO_DEFAULT_RULES = [
    "/etc/falco/falco_rules.yaml",
    "/etc/falco/falco_rules.local.yaml",
]
CUSTOM_RULES_DIR = ROOT / "falco" / "rules.d"
CUSTOM_RULES = sorted(str(p) for p in CUSTOM_RULES_DIR.glob("*.yaml"))

SCENARIOS = {
    "s1_dockersock": f"bash {SCEN_DIR / 's1_dockersock.sh'}",
    "s2_priv_pid_host": f"bash {SCEN_DIR / 's2_priv_pid_host.sh'}",
    "s3_host_mount": f"bash {SCEN_DIR / 's3_host_mount.sh'}",
}

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

CUSTOM_RULE_NAMES = LAYER1_RULES | LAYER2_RULES

FALCO_START_TIMEOUT = 10
FALCO_WARMUP_TIME = 3
FALCO_STOP_TIMEOUT = 10
SCENARIO_TIMEOUT_BUFFER = 5
FLUSH_WAIT_TIME = 3

def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def parse_evt_time(timestamp_str: str) -> datetime:
    timestamp_str = timestamp_str.rstrip("Z")
    if "." in timestamp_str:
        head, frac = timestamp_str.split(".", 1)
        frac = (frac + "000000")[:6]
        timestamp_str = f"{head}.{frac}"
    try:
        return datetime.fromisoformat(timestamp_str).replace(tzinfo=timezone.utc)
    except ValueError as e:
        logger.warning(f"Failed to parse timestamp '{timestamp_str}': {e}")
        return datetime.now(timezone.utc)

def parse_evt_time_iso8601_to_ns(ts: str) -> int:
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
        if len(frac_digits) > 9:
            frac_digits = frac_digits[:9]
        else:
            frac_digits = frac_digits.ljust(9, "0")
        try:
            frac_ns = int(frac_digits)
        except ValueError:
            frac_ns = 0
        base_str = s_no_frac
    else:
        base_str = s

    if z and not base_str.endswith("Z"):
        base_str = base_str + "Z"

    try:
        if base_str.endswith("Z"):
            base_dt = datetime.fromisoformat(base_str[:-1]).replace(tzinfo=timezone.utc)
        else:
            base_dt = datetime.fromisoformat(base_str)
            if base_dt.tzinfo is None:
                base_dt = base_dt.replace(tzinfo=timezone.utc)
    except Exception:
        base_dt = datetime.now(timezone.utc)

    sec_ns = int(base_dt.timestamp()) * 1_000_000_000
    return sec_ns + frac_ns

def validate_environment() -> bool:
    missing_rules = [r for r in FALCO_DEFAULT_RULES if not Path(r).exists()]
    if missing_rules:
        logger.error(f"Missing default rule files: {missing_rules}")
        return False

    for name, cmd in SCENARIOS.items():
        script_path = cmd.split()[1]
        if not Path(script_path).exists():
            logger.error(f"Scenario script missing: {script_path}")
            return False

    try:
        subprocess.run(["which", "falco"], check=True, capture_output=True)
    except subprocess.CalledProcessError:
        logger.error("Falco binary not found in PATH")
        return False

    try:
        result = subprocess.run(
            ["systemctl", "is-active", "falco"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            logger.warning("Falco service is running, attempting to stop it...")
            subprocess.run(["sudo", "systemctl", "stop", "falco"], check=True)
            time.sleep(2)
    except Exception:
        pass

    return True

def start_falco(logfile: Path, mode: str) -> Optional[subprocess.Popen]:
    try:
        subprocess.run(["sudo", "pkill", "-9", "falco"], capture_output=True, timeout=5)
        time.sleep(0.5)
    except Exception:
        pass
    args = [
        "sudo",
        "falco",
        "-o", "json_output=true",
        "-o", "time_format_iso_8601=true",
        "-o", f"file_output.enabled=true",
        "-o", f"file_output.filename={logfile}",
        "-o", "file_output.keep_alive=false",
        "-o", "stdout_output.enabled=false",
        "-o", "syslog_output.enabled=false",
        "-o", "buffered_outputs=false",
        "-o", "syscall_event_drops.actions=ignore",
        "-o", "syscall_event_drops.threshold=0.1",
        "-o", "grpc.enabled=false",
        "-o", "webserver.enabled=false",
        "-o", "http_output.enabled=true",
        "-o", "http_output.url=http://localhost:2801",
    ]

    for rule_file in FALCO_DEFAULT_RULES:
        if Path(rule_file).exists():
            args.extend(["-r", rule_file])

    if mode == "custom":
        for rule_file in CUSTOM_RULES:
            args.extend(["-r", rule_file])

    try:
        import tempfile
        temp_fd, temp_logfile = tempfile.mkstemp(suffix='.jsonl', prefix='falco_')
        os.close(temp_fd)
        os.chmod(temp_logfile, 0o666)

        for i, arg in enumerate(args):
            if arg.startswith("file_output.filename="):
                args[i] = f"file_output.filename={temp_logfile}"
                break

        proc = subprocess.Popen(
            args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid
        )

        proc._temp_logfile = temp_logfile
        proc._final_logfile = logfile

        logger.debug(f"Starting Falco (PID: {proc.pid}) in {mode} mode...")

        time.sleep(1)
        if proc.poll() is not None:
            stdout, stderr = proc.communicate()
            logger.error(f"Falco failed to start: {stderr.decode()}")
            return None

        logger.debug(f"Falco started successfully (PID: {proc.pid})")
        return proc

    except Exception as e:
        logger.error(f"Failed to start Falco: {e}")
        return None

def stop_falco(proc: subprocess.Popen) -> None:
    if proc is None:
        return

    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        proc.wait(timeout=FALCO_STOP_TIMEOUT)
        logger.debug(f"Falco (PID: {proc.pid}) stopped gracefully")
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            proc.wait(timeout=2)
            logger.warning(f"Falco (PID: {proc.pid}) force killed")
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
                logger.debug(f"Copied Falco output from {proc._temp_logfile} to {proc._final_logfile}")
        except Exception as e:
            logger.warning(f"Failed to copy Falco log file: {e}")

    if hasattr(proc, '_logfile_fd'):
        try:
            proc._logfile_fd.close()
        except Exception:
            pass

def warm_up_falco(warmup_sec: int) -> None:
    logger.debug("Warming up Falco...")

    time.sleep(warmup_sec)

    try:
        subprocess.run(
            ["docker", "run", "--rm", "alpine:latest", "echo", "warmup"],
            capture_output=True,
            timeout=5
        )
    except Exception:
        pass

    time.sleep(1)

def parse_falco_events(logfile: Path, t0_ns: int, capture_t0_ns: Optional[int] = None) -> List[Dict]:
    events = []

    if not logfile.exists():
        logger.warning(f"Log file not found: {logfile}")
        return events

    time.sleep(0.5)

    t0_iso = datetime.fromtimestamp(t0_ns / 1_000_000_000, tz=timezone.utc).isoformat()

    with logfile.open() as f:
        for line_num, line in enumerate(f, 1):
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

            latency_ms = (evt_ns - t0_ns) // 1_000_000
            evt["_latency_ms"] = int(latency_ms)
            evt["_capture_offset_ms"] = int((evt_ns - (capture_t0_ns or t0_ns)) // 1_000_000)
            evt["_t0"] = t0_iso

            events.append(evt)

    return events

def run_scenario(cmd: str, timeout: int) -> Tuple[int, str]:
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            timeout=timeout,
            capture_output=True,
            text=True
        )
        return result.returncode, ""
    except subprocess.TimeoutExpired:
        return 124, "Scenario timeout exceeded"
    except Exception as e:
        return 1, str(e)

def run_one_experiment(
    mode: str,
    scen_name: str,
    cmd: str,
    window_sec: int,
    warmup_sec: int,
    outstamp: str,
    run_num: int,
    workload_session: Optional[WorkloadSession] = None,
) -> Dict:
    run_dir = OUT_DIR / batch_label(outstamp, bool(workload_session and workload_session.active)) / mode
    run_dir.mkdir(parents=True, exist_ok=True)
    logfile = run_dir / f"{scen_name}_run{run_num:02d}.jsonl"

    if logfile.exists():
        logfile.unlink()

    falco = start_falco(logfile, mode)
    if falco is None:
        return {
            "timestamp": outstamp,
            "mode": mode,
            "scenario": scen_name,
            "run_num": run_num,
            "scen_rc": -1,
            "scen_err": "Failed to start Falco",
            "events": 0,
            "unique_rules": "",
            "detected_any": 0,
            "detected_customrule": 0,
            "detected_layer2": 0,
            "first_latency_ms": None,
            "first_layer2_latency_ms": None,
            "custom_events": 0,
            "layer1_count": 0,
            "layer2_count": 0,
            "noise_events": 0,
            "snr": 0.0,
            "median_latency_ms": None,
            "p95_latency_ms": None,
            "p99_latency_ms": None,
            "latencies_ms": [],
            "event_offsets_ms": [],
            "layer2_rules_fired": [],
            "rule_counts": {},
            "workload_active": bool(workload_session and workload_session.active),
            "capture_pre_window_sec": workload_session.pre_capture_sec if workload_session and workload_session.active else 0,
            "attack_offset_ms": (workload_session.pre_capture_sec if workload_session and workload_session.active else 0) * 1000,
            "resource_csv": str(workload_session.resource_csv) if workload_session and workload_session.active else "",
            "logfile": str(logfile),
        }

    time.sleep(max(2, warmup_sec))

    warm_up_falco(warmup_sec)

    pre_capture_sec = workload_session.pre_capture_sec if workload_session and workload_session.active else 0
    capture_t0_ns = time.time_ns()
    if pre_capture_sec > 0:
        time.sleep(pre_capture_sec)

    t0_ns = time.time_ns()

    scenario_timeout = max(window_sec // 2, 10)
    scen_rc, scen_err = run_scenario(cmd, scenario_timeout)

    flush_time = max(3, window_sec - scenario_timeout)
    time.sleep(flush_time)

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

    for evt in events:
        evt["_mode"] = mode
        evt["_scenario"] = scen_name
        evt["_run_num"] = run_num

    has_any = len(events) > 0
    unique_rules = sorted({e["rule"] for e in events})

    custom_hits = [e for e in events if e.get("rule") in CUSTOM_RULE_NAMES]
    has_custom = len(custom_hits) > 0
    has_layer2 = metrics["layer2_count"] > 0

    if events:
        logger.debug(f"  Detected rules: {unique_rules}")
        if mode == "custom" and not has_custom:
            logger.warning(f"  No custom rules fired, only defaults: {unique_rules}")

    if events:
        full_events_path = DATA_DIR / "events_experiments.jsonl"
        with full_events_path.open("a") as outf:
            for evt in events:
                outf.write(json.dumps(evt, default=str) + "\n")

    return {
        "timestamp": outstamp,
        "mode": mode,
        "scenario": scen_name,
        "run_num": run_num,
        "scen_rc": scen_rc,
        "scen_err": scen_err,
        "events": len(events),
        "unique_rules": "|".join(unique_rules),
        "detected_any": int(has_any),
        "detected_customrule": int(has_custom),
        "detected_layer2": int(has_layer2),
        "first_latency_ms": metrics["first_latency_ms"],
        "first_layer2_latency_ms": metrics["first_layer2_latency_ms"],
        "custom_events": len(custom_hits),
        "layer1_count": metrics["layer1_count"],
        "layer2_count": metrics["layer2_count"],
        "noise_events": metrics["noise_events"],
        "snr": metrics["snr"],
        "median_latency_ms": metrics["median_latency_ms"],
        "p95_latency_ms": metrics["p95_latency_ms"],
        "p99_latency_ms": metrics["p99_latency_ms"],
        "latencies_ms": metrics["latencies_ms"],
        "event_offsets_ms": metrics["event_offsets_ms"],
        "layer2_rules_fired": metrics["layer2_rules_fired"],
        "rule_counts": metrics["rule_counts"],
        "workload_active": bool(workload_session and workload_session.active),
        "capture_pre_window_sec": pre_capture_sec,
        "attack_offset_ms": pre_capture_sec * 1000,
        "resource_csv": str(workload_session.resource_csv) if workload_session and workload_session.active else "",
        "logfile": str(logfile),
    }

def create_summary_reports(
    df: pd.DataFrame,
    outstamp: str,
    *,
    workload_enabled: bool,
    workload_session: Optional[WorkloadSession],
) -> None:
    label = batch_label(outstamp, workload_enabled)

    df_path = DATA_DIR / f"summary_{label}.csv"
    csv_df = df.copy()
    for column in ("latencies_ms", "event_offsets_ms", "layer2_rules_fired", "rule_counts"):
        if column in csv_df.columns:
            csv_df[column] = csv_df[column].apply(json_dumps)
    csv_df.to_csv(df_path, index=False)
    logger.info(f"Summary saved: {df_path}")

    coverage_stats = []
    for mode in df["mode"].unique():
        for scenario in df["scenario"].unique():
            subset = df[(df["mode"] == mode) & (df["scenario"] == scenario)]
            if subset.empty:
                continue

            coverage_stats.append({
                "mode": mode,
                "scenario": scenario,
                "workload_active": int(subset["workload_active"].max()) if "workload_active" in subset else 0,
                "total_runs": len(subset),
                "detection_rate": subset["detected_any"].mean(),
                "custom_rule_rate": subset["detected_customrule"].mean() if mode == "custom" else None,
                "layer2_detection_rate": subset["detected_layer2"].mean() if "detected_layer2" in subset else None,
                "avg_events": subset["events"].mean(),
                "avg_custom_events": subset["custom_events"].mean() if mode == "custom" else None,
                "avg_layer1_events": subset["layer1_count"].mean() if "layer1_count" in subset else None,
                "avg_layer2_events": subset["layer2_count"].mean() if "layer2_count" in subset else None,
                "avg_noise_events": subset["noise_events"].mean() if "noise_events" in subset else None,
                "avg_snr": subset["snr"].mean() if "snr" in subset else None,
            })

    cov_df = pd.DataFrame(coverage_stats)
    cov_path = DATA_DIR / f"coverage_{label}.csv"
    cov_df.to_csv(cov_path, index=False)
    logger.info(f"Coverage analysis saved: {cov_path}")

    rule_stats = []
    for mode in df["mode"].unique():
        for scenario in df["scenario"].unique():
            subset = df[(df["mode"] == mode) & (df["scenario"] == scenario)]
            if subset.empty:
                continue
            n = len(subset)
            row = {"mode": mode, "scenario": scenario, "runs": n,
                   "detection_rate": f"{subset['detected_any'].mean()*100:.1f}%"}
            for rule in sorted(CUSTOM_RULE_NAMES):
                fired = sum(1 for _, r in subset.iterrows()
                            if rule in str(r.get("unique_rules", "")))
                row[rule] = f"{fired}/{n}"
            rule_stats.append(row)
    if rule_stats:
        rule_df = pd.DataFrame(rule_stats)
        rule_path = DATA_DIR / f"per_rule_{label}.csv"
        rule_df.to_csv(rule_path, index=False)
        logger.info(f"Per-rule breakdown saved: {rule_path}")
    else:
        rule_path = None

    df_with_latency = df[df["first_layer2_latency_ms"].notna()]
    if not df_with_latency.empty:
        latency_stats = []
        for mode in df_with_latency["mode"].unique():
            for scenario in df_with_latency["scenario"].unique():
                subset = df_with_latency[
                    (df_with_latency["mode"] == mode) &
                    (df_with_latency["scenario"] == scenario)
                ]
                if subset.empty:
                    continue

                latency_stats.append({
                    "mode": mode,
                    "scenario": scenario,
                    "workload_active": int(subset["workload_active"].max()) if "workload_active" in subset else 0,
                    "median_ms": subset["first_layer2_latency_ms"].median(),
                    "mean_ms": subset["first_layer2_latency_ms"].mean(),
                    "std_ms": subset["first_layer2_latency_ms"].std(),
                    "min_ms": subset["first_layer2_latency_ms"].min(),
                    "max_ms": subset["first_layer2_latency_ms"].max(),
                    "samples": len(subset),
                })

        lat_df = pd.DataFrame(latency_stats)
        lat_path = DATA_DIR / f"latency_{label}.csv"
        lat_df.to_csv(lat_path, index=False)
        logger.info(f"Latency analysis saved: {lat_path}")
    else:
        lat_path = None

    symlink_map = [
        (
            "summary_workload_latest.csv" if workload_enabled else "summary_latest.csv",
            df_path,
        ),
        (
            "coverage_workload_latest.csv" if workload_enabled else "coverage_latest.csv",
            cov_path,
        ),
    ]
    if lat_path:
        symlink_map.append((
            "latency_workload_latest.csv" if workload_enabled else "latency_latest.csv",
            lat_path,
        ))
    if rule_path:
        symlink_map.append((
            "per_rule_workload_latest.csv" if workload_enabled else "per_rule_latest.csv",
            rule_path,
        ))
    if workload_enabled and workload_session:
        symlink_map.append(("resource_usage_workload_latest.csv", workload_session.resource_csv))

    for symlink_name, target_path in symlink_map:
        symlink = DATA_DIR / symlink_name
        if symlink.exists() or symlink.is_symlink():
            symlink.unlink()
        symlink.symlink_to(target_path.name)

def print_experiment_summary(df: pd.DataFrame) -> None:
    logger.info("\n" + "=" * 70)
    logger.info("EXPERIMENT SUMMARY")
    logger.info("=" * 70)

    for mode in sorted(df["mode"].unique()):
        mode_df = df[df["mode"] == mode]
        logger.info(f"\n{mode.upper()} MODE RESULTS:")
        logger.info("-" * 50)

        overall_detection = mode_df["detected_any"].mean() * 100
        logger.info(f"Overall detection rate: {overall_detection:.1f}%")

        if mode == "custom":
            custom_rule_rate = mode_df["detected_customrule"].mean() * 100
            logger.info(f"Custom rule firing rate: {custom_rule_rate:.1f}%")

        logger.info("\nPer-scenario breakdown:")
        for scenario in sorted(df["scenario"].unique()):
            scen_df = mode_df[mode_df["scenario"] == scenario]
            if scen_df.empty:
                continue

            detection_rate = scen_df["detected_any"].mean() * 100
            avg_events = scen_df["events"].mean()
            avg_layer1 = scen_df["layer1_count"].mean() if "layer1_count" in scen_df else 0
            avg_layer2 = scen_df["layer2_count"].mean() if "layer2_count" in scen_df else 0
            avg_snr = scen_df["snr"].mean() if "snr" in scen_df else 0

            latency_df = scen_df[scen_df["first_layer2_latency_ms"].notna()]
            if not latency_df.empty:
                median_latency = latency_df["first_layer2_latency_ms"].median()
                min_latency = latency_df["first_layer2_latency_ms"].min()
                max_latency = latency_df["first_layer2_latency_ms"].max()
                latency_str = f", latency: {median_latency:.0f}ms (range: {min_latency:.0f}-{max_latency:.0f}ms)"
            else:
                latency_str = ", latency: N/A"

            logger.info(
                f"  • {scenario}: detection={detection_rate:.0f}%, "
                f"events={avg_events:.1f}, L1={avg_layer1:.1f}, L2={avg_layer2:.1f}, SNR={avg_snr:.4f}{latency_str}"
            )

            if mode == "custom":
                custom_rate = scen_df["detected_customrule"].mean() * 100
                avg_custom = scen_df["custom_events"].mean()
                logger.info(
                    f"    └─ Custom rules: {custom_rate:.0f}% firing rate, "
                    f"{avg_custom:.1f} custom events/run"
                )

    logger.info("\n" + "=" * 70)

def main():
    parser = argparse.ArgumentParser(
        description="Run Falco detection experiments on container escape scenarios",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=10,
        help="Number of repetitions per scenario per mode"
    )
    parser.add_argument(
        "--window",
        type=int,
        default=30,
        help="Total time budget (seconds) per scenario run"
    )
    parser.add_argument(
        "--warmup",
        type=int,
        default=3,
        help="Seconds to warm up Falco before running scenario"
    )
    parser.add_argument(
        "--mode",
        choices=["baseline", "custom", "both"],
        default="both",
        help="Rule mode: baseline (default only), custom (default+custom), or both"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    parser.add_argument(
        "--workload",
        action="store_true",
        help="Run with continuous background workload"
    )

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logging.getLogger().setLevel(logging.DEBUG)

    logger.info("Validating environment...")
    if not validate_environment():
        logger.error("Environment validation failed")
        sys.exit(2)

    if args.mode in ("custom", "both"):
        if not CUSTOM_RULES:
            logger.error("No custom rules found under falco/rules.d/*.yaml")
            sys.exit(2)
        logger.info(f"Found {len(CUSTOM_RULES)} custom rule files")
        for rule_file in CUSTOM_RULES:
            logger.info(f"  • {Path(rule_file).name}")

    outstamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    logger.info(f"Starting experiment batch: {batch_label(outstamp, args.workload)}")
    logger.info(f"Configuration: {args.runs} runs, {args.warmup}s warmup, {args.window}s window")

    modes = ["baseline", "custom"] if args.mode == "both" else [args.mode]

    results = []
    total_runs = len(modes) * len(SCENARIOS) * args.runs
    current_run = 0

    workload_session: Optional[WorkloadSession] = None
    try:
        if args.workload:
            workload_session = start_workload(outstamp, logger)

        for mode in modes:
            logger.info(f"\n{'='*50}")
            logger.info(f"Running {mode.upper()} mode experiments...")
            logger.info(f"{'='*50}")

            for scen_name, cmd in SCENARIOS.items():
                logger.info(f"\nScenario: {scen_name}")

                for run_num in range(args.runs):
                    current_run += 1
                    progress = f"[{current_run}/{total_runs}]"

                    logger.info(
                        f"{progress} Run {run_num + 1}/{args.runs} "
                        f"({mode} mode)"
                    )

                    result = run_one_experiment(
                        mode=mode,
                        scen_name=scen_name,
                        cmd=cmd,
                        window_sec=args.window,
                        warmup_sec=args.warmup,
                        outstamp=outstamp,
                        run_num=run_num + 1,
                        workload_session=workload_session,
                    )
                    results.append(result)

                    if result["detected_any"]:
                        status = "✓ DETECTED"
                        latency_value = result["first_layer2_latency_ms"]
                        latency_text = f"{latency_value}ms" if latency_value is not None else "N/A"
                        details = (
                            f"{result['events']} events, L1={result['layer1_count']}, "
                            f"L2={result['layer2_count']}, first L2 at {latency_text}, "
                            f"SNR={result['snr']:.4f}"
                        )
                        if mode == "custom" and result["detected_customrule"]:
                            details += f" ({result['custom_events']} custom)"
                    else:
                        status = "✗ MISSED"
                        details = "No events detected"

                    logger.info(f"  → {status}: {details}")

        df = pd.DataFrame(results)
        create_summary_reports(
            df,
            outstamp,
            workload_enabled=args.workload,
            workload_session=workload_session,
        )

        print_experiment_summary(df)

        logger.info("\nKEY METRICS:")
        baseline_df = df[df["mode"] == "baseline"]
        custom_df = df[df["mode"] == "custom"]

        if not baseline_df.empty:
            baseline_coverage = baseline_df["detected_any"].mean() * 100
            logger.info(f"  Baseline coverage: {baseline_coverage:.1f}%")

        if not custom_df.empty:
            custom_coverage = custom_df["detected_any"].mean() * 100
            custom_rule_coverage = custom_df["detected_customrule"].mean() * 100
            layer2_coverage = custom_df["detected_layer2"].mean() * 100 if "detected_layer2" in custom_df else 0
            logger.info(f"  Custom mode coverage: {custom_coverage:.1f}%")
            logger.info(f"  Custom rule firing: {custom_rule_coverage:.1f}%")
            logger.info(f"  Layer 2 coverage: {layer2_coverage:.1f}%")

        logger.info(f"\nResults saved to: {DATA_DIR}")
        logger.info(f"Per-run logs: {OUT_DIR / batch_label(outstamp, args.workload)}")
    finally:
        stop_workload(workload_session, logger)

if __name__ == "__main__":
    main()
