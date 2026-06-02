#!/usr/bin/env python3
"""
Quick results analyzer for container security experiments.
Generates summary statistics and identifies if targets are met.
"""

import sys
from pathlib import Path

try:
    import pandas as pd
except ImportError:
    print("ERROR: pandas not installed")
    print("Install with: sudo apt install python3-pandas")
    sys.exit(1)

def analyze_results(timestamp=None):
    data_dir = Path(__file__).parent / "results"

    if timestamp:
        summary_file = data_dir / f"summary_{timestamp}.csv"
        coverage_file = data_dir / f"coverage_{timestamp}.csv"
        latency_file = data_dir / f"latency_{timestamp}.csv"
    else:
        summary_file = data_dir / "summary_latest.csv"
        coverage_file = data_dir / "coverage_latest.csv"
        latency_file = data_dir / "latency_latest.csv"

    if not summary_file.exists():
        print(f"ERROR: Summary file not found: {summary_file}")
        print("\nRun experiments first:")
        print("  python3 experiments/run_experiments.py --runs 12 --mode both")
        sys.exit(1)

    summary = pd.read_csv(summary_file)
    coverage = pd.read_csv(coverage_file) if coverage_file.exists() else None
    latency = pd.read_csv(latency_file) if latency_file.exists() else None

    print("=" * 70)
    print("EXPERIMENT RESULTS ANALYSIS")
    print("=" * 70)
    print()

    print("OVERALL STATISTICS")
    print("-" * 70)
    print(f"Total runs: {len(summary)}")
    print(f"Scenarios: {summary['scenario'].nunique()}")
    print(f"Modes: {', '.join(summary['mode'].unique())}")
    print()

    if 'custom' in summary['mode'].values:
        custom = summary[summary['mode'] == 'custom']

        print("CUSTOM MODE PERFORMANCE")
        print("-" * 70)

        detection_rate = custom['detected_any'].mean() * 100
        custom_rule_rate = custom['detected_customrule'].mean() * 100
        avg_events = custom['events'].mean()
        avg_custom_events = custom['custom_events'].mean()

        print(f"Detection rate: {detection_rate:.1f}%")
        target_status = 'TARGET MET' if custom_rule_rate >= 95 else 'BELOW TARGET'
        print(f"Custom rule hit rate: {custom_rule_rate:.1f}% ({target_status})")
        print(f"Average events per run: {avg_events:.1f}")
        print(f"Average custom events per run: {avg_custom_events:.1f}")
        print()

        print("Per-scenario custom rule performance:")
        for scenario in sorted(custom['scenario'].unique()):
            scen_data = custom[custom['scenario'] == scenario]
            scen_custom_rate = scen_data['detected_customrule'].mean() * 100
            scen_events = scen_data['custom_events'].mean()
            status = "[PASS]" if scen_custom_rate >= 95 else "[FAIL]"
            print(f"  {status} {scenario}: {scen_custom_rate:.1f}% hit rate, {scen_events:.1f} custom events/run")
        print()

    if 'baseline' in summary['mode'].values:
        baseline = summary[summary['mode'] == 'baseline']

        print("BASELINE MODE PERFORMANCE")
        print("-" * 70)

        detection_rate = baseline['detected_any'].mean() * 100
        avg_events = baseline['events'].mean()

        print(f"Detection rate: {detection_rate:.1f}%")
        print(f"Average events per run: {avg_events:.1f}")
        print()

        print("Per-scenario baseline performance:")
        for scenario in sorted(baseline['scenario'].unique()):
            scen_data = baseline[baseline['scenario'] == scenario]
            scen_rate = scen_data['detected_any'].mean() * 100
            scen_events = scen_data['events'].mean()
            print(f"  • {scenario}: {scen_rate:.1f}% detection, {scen_events:.1f} events/run")
        print()

    if latency is not None and not latency.empty:
        print("LATENCY ANALYSIS")
        print("-" * 70)

        summary_with_latency = summary[summary['first_latency_ms'].notna()]
        if not summary_with_latency.empty:
            min_latency = summary_with_latency['first_latency_ms'].min()
            if min_latency < 0:
                print(f"ISSUE: Negative latencies detected (min: {min_latency:.1f}ms)")
            else:
                print(f"No negative latencies (min: {min_latency:.1f}ms)")
            print()

        print("Latency by scenario and mode:")
        print()
        print(f"{'Scenario':<20} {'Mode':<10} {'Median':<10} {'Mean':<10} {'StdDev':<10} {'Min':<8} {'Max':<8}")
        print("-" * 76)

        for _, row in latency.iterrows():
            print(f"{row['scenario']:<20} {row['mode']:<10} "
                  f"{row['median_ms']:<10.1f} {row['mean_ms']:<10.1f} "
                  f"{row['std_ms']:<10.1f} {row['min_ms']:<8.1f} {row['max_ms']:<8.1f}")

        print()

        max_stddev = latency['std_ms'].max()
        if max_stddev < 100:
            print(f"Latency is stable (max stddev: {max_stddev:.1f}ms)")
        else:
            print(f"WARNING: Latency varies significantly (max stddev: {max_stddev:.1f}ms)")
        print()

    if 'custom' in summary['mode'].values:
        print("RULE FIRING ANALYSIS (Custom Mode)")
        print("-" * 70)

        custom = summary[summary['mode'] == 'custom']

        all_rules = []
        for rules_str in custom['unique_rules']:
            if pd.notna(rules_str) and rules_str:
                all_rules.extend(rules_str.split('|'))

        if all_rules:
            rule_counts = pd.Series(all_rules).value_counts()
            print(f"\nTop 10 most frequent rules (out of {len(custom)} runs):")
            for rule, count in rule_counts.head(10).items():
                pct = count / len(custom) * 100
                print(f"  {pct:5.1f}% ({count:3d}x) {rule}")
        print()

    print("=" * 70)
    print("SUCCESS CRITERIA CHECK")
    print("=" * 70)
    print()

    success = True

    if 'custom' in summary['mode'].values:
        custom = summary[summary['mode'] == 'custom']
        custom_rule_rate = custom['detected_customrule'].mean() * 100

        print(f"1. Custom rule hit rate ≥95%: ", end="")
        if custom_rule_rate >= 95:
            print(f"PASS ({custom_rule_rate:.1f}%)")
        else:
            print(f"FAIL ({custom_rule_rate:.1f}%)")
            success = False

    if latency is not None:
        summary_with_latency = summary[summary['first_latency_ms'].notna()]
        if not summary_with_latency.empty:
            min_latency = summary_with_latency['first_latency_ms'].min()
            print(f"2. No negative latencies: ", end="")
            if min_latency >= 0:
                print(f"PASS (min: {min_latency:.1f}ms)")
            else:
                print(f"FAIL (min: {min_latency:.1f}ms)")
                success = False

            max_stddev = latency['std_ms'].max()
            print(f"3. Latency stability (stddev <100ms): ", end="")
            if max_stddev < 100:
                print(f"PASS ({max_stddev:.1f}ms)")
            else:
                print(f"WARNING ({max_stddev:.1f}ms)")

    print()

    if success:
        print("ALL CRITERIA MET - RESULTS READY TO FREEZE")
    else:
        print("SOME CRITERIA NOT MET - REVIEW RESULTS")

    print()
    print("=" * 70)
    print()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        timestamp = sys.argv[1]
        print(f"Analyzing results for timestamp: {timestamp}\n")
        analyze_results(timestamp)
    else:
        print("Analyzing latest results...\n")
        analyze_results()
