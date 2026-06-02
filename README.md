# Container Security Lab

A runtime container-security monitoring lab built on [Falco](https://falco.org). The repo contains:

- A layered custom Falco ruleset for three representative container-escape scenarios.
- An experiment harness that runs the scenarios under baseline and custom rules and collects detection metrics.
- An evasion harness that runs 8 evasion techniques against the custom rules and records which rules survive.
- A detection-anchor taxonomy that classifies Falco condition fields by what the attacker can or cannot manipulate.
- A static rule auditor that applies the taxonomy to any Falco YAML ruleset and produces text, CSV, JSON, or HTML reports.

The motivating question: *can Falco reliably detect container escapes, and what makes some rules resistant to evasion while others fail?*

## Layout

```
container-sec-lab/
├── falco/rules.d/            custom Falco rules (4 files, 13 rules)
├── scenarios/                Phase 1 escape scenarios (S1, S2, S3)
├── scenarios/evasion/        Phase 2 evasion scenarios (E1, E1b, E2, E3a, E3b, E4, E5, E6)
├── scenarios/evasion/helpers/   C helper source used by E1b (join_ns.c)
├── taxonomy/                 anchor classes + field classifications used by the auditor
├── auditor/                  rule auditor + tests
├── experiments/              experiment runners (Phase 1, Phase 2, workload support)
├── workload/                 background load driver and resource monitor
├── docker-compose.workload.yaml         4-container workload stack
├── docker-compose.falcosidekick.yaml    Falcosidekick + UI stack
├── setup.sh                  install Docker, Falco, eBPF tools, project venv
├── run_experiment.sh         Phase 1 harness (`quick` or `full`)
├── analyze_results.py        summarize the latest run
├── start_falco_live.sh       Terminal 1 - start Falco with custom rules
├── watch_events.sh           Terminal 2 - tail formatted events
├── sidekick.sh               bring the Falcosidekick + UI stack up/down
└── sidekick_dashboard.sh     replay archived JSONL into the UI
```

## Custom Falco Rules

13 rules across 4 files in `falco/rules.d/`.

**Layer 1 - broad activity coverage** (`05-container-activity.yaml`):
- Container Process Spawned, File Activity, Network Connection, Reading Sensitive Paths, Using System Tools.

**Layer 2 - escape-specific high-confidence detections** (`10-dockersock.yaml`, `20-host-mount-write.yaml`, `30-setns-or-nsenter.yaml`):
- Docker Socket Access (path-anchored), Unix Socket Connection (syscall-anchored), Docker Socket Mounted (mount-anchored).
- setns Syscall (syscall-anchored), unshare Syscall (syscall-anchored), nsenter binary (name-anchored).
- Writing Under Mounted Host Root (path-anchored), Host Root Mounted (mount-anchored).

`rule_matching=all` is required for layered detection so Layer 2 rules can fire on the same event as Layer 1.

## Attack Scenarios

| Scenario | What it models |
|---|---|
| `scenarios/s1_dockersock.sh` | Docker socket escape - privileged container with `/var/run/docker.sock` mounted in. |
| `scenarios/s2_priv_pid_host.sh` | Namespace-based host access - privileged container with host PID namespace, calls `setns` / `nsenter`. |
| `scenarios/s3_host_mount.sh` | Host filesystem tampering - container with host root mounted, writes through the mount. |

Phase 2 evasion scenarios under `scenarios/evasion/`:

| File | Technique |
|---|---|
| `e1_binary_rename.sh` | Rename `nsenter` to a different path. |
| `e1b_custom_setns.sh` | Custom C binary calling `setns()` directly (no `nsenter` string anywhere). |
| `e2_unshare.sh` | Use `unshare` syscall instead of `setns`. |
| `e3a_symlink_only.sh` | Access `docker.sock` through a symlink. |
| `e3b_fd_redirect_only.sh` | Access `docker.sock` through fd redirection. |
| `e4_symlink_hostmount.sh` | Access host mount through a symlinked path. |
| `e5_false_positive.sh` | Benign workload - false-positive baseline. |
| `e6_startup_timing.sh` | Run an escape during Falco's eBPF-probe attachment window. |

## Install

Ubuntu 22.04 / 24.04 / 25.04, root or sudo access:

```bash
bash setup.sh
```

`setup.sh` installs Docker, Falco, eBPF tools, and creates a project venv under `./venv` from `requirements.txt` (`pandas`, `pyyaml`, `numpy`). It detects a broken venv (e.g. after a Python version upgrade) and rebuilds it.

## Run experiments

**Quick smoke test** (1 run × 3 scenarios, custom mode only, ~2 min):

```bash
sudo bash run_experiment.sh quick
```

**Phase 1 full** (10 runs × 3 scenarios × baseline+custom, with workload, ~30 min):

```bash
sudo venv/bin/python3 experiments/run_experiments.py --runs 10 --mode both --workload
```

**Phase 2 evasion** (skip the false-positive and startup tests for speed):

```bash
sudo venv/bin/python3 experiments/run_evasion_experiments.py --runs 10 --workload --skip-e5 --skip-e6
```

Summarize the latest run:

```bash
venv/bin/python3 analyze_results.py
```

## Live monitoring

Two-terminal workflow:

```bash
# Terminal 1
sudo bash start_falco_live.sh

# Terminal 2
bash watch_events.sh
```

For the Falcosidekick UI stack:

```bash
bash sidekick.sh up        # http://localhost:2802/ui
bash sidekick.sh down
```

## Rule Auditor

The auditor takes any Falco YAML and predicts whether each rule will survive realistic evasion.

```bash
# Audit the custom rules
venv/bin/python3 auditor/falco_rule_auditor.py falco/rules.d/

# Audit Falco's upstream defaults
venv/bin/python3 auditor/falco_rule_auditor.py /etc/falco/falco_rules.yaml

# HTML report
venv/bin/python3 auditor/falco_rule_auditor.py falco/rules.d/ --format html -o audit_report.html

# Run the test suite
venv/bin/python3 -m unittest auditor.test_auditor
```

See [auditor/README.md](auditor/README.md) for usage details and [taxonomy/README.md](taxonomy/README.md) for the anchor classification rules.

## Output

Experiment harnesses write to `results/`:

- `results/runs/<batch>/<baseline|custom>/<scenario>_runNN.jsonl` - raw Falco events per run.
- `results/summary_<batch>.csv` - aggregate detection rates per scenario.
- `results/coverage_<batch>.csv`, `latency_<batch>.csv`, `per_rule_<batch>.csv` - derived metrics.
- `results/evasion_results_<batch>.json` + `evasion_csv_<batch>.csv` + `evasion_summary_<batch>.txt` - Phase 2 outputs.

These are gitignored - large per-run logs stay local. Re-run the harness to regenerate.

## Notes

- Snap-installed Docker has AppArmor edge cases that can leave containers stuck. `sidekick.sh down` handles them via `cgroup.kill`.
- Falco must be run with `-o rule_matching=all` for layered detection to work.
- The custom rules reference Falco's default `container` macro, so `/etc/falco/falco_rules.yaml` must be loaded alongside them.
