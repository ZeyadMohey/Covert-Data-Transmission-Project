"""Offline analysis runner: drives performance, integrity, and statistical modules.

Reads captures from metrics/output/captures/, writes results to
metrics/output/results/, and emits a plain-text summary report.

Usage:
    python -m metrics.runner [--captures-dir DIR] [--results-dir DIR] [--verbose]
"""

import argparse
import os
from pathlib import Path
from datetime import datetime

import pandas as pd

from metrics import performance, integrity, statistical

DEFAULT_CAPTURES = "metrics/output/captures"
DEFAULT_RESULTS = "metrics/output/results"


def run_all_analyses(captures_dir=DEFAULT_CAPTURES, results_dir=DEFAULT_RESULTS, verbose=False):
    """Run each analysis module, skipping any whose captures are missing."""
    os.makedirs(results_dir, exist_ok=True)
    status = {}

    try:
        if verbose:
            print("[RUNNER] Running performance analysis...")
        performance.run_all(captures_dir=captures_dir, results_dir=results_dir)
        status["performance"] = "ok"
    except FileNotFoundError as e:
        print(f"[RUNNER] WARNING: Performance analysis skipped -- {e}")
        status["performance"] = f"skipped: {e}"
    except Exception as e:
        print(f"[RUNNER] ERROR: Performance analysis failed -- {e}")
        status["performance"] = f"error: {e}"

    try:
        if verbose:
            print("[RUNNER] Running integrity analysis...")
        integrity.run_all(results_dir=results_dir)
        status["integrity"] = "ok"
    except Exception as e:
        print(f"[RUNNER] ERROR: Integrity analysis failed -- {e}")
        status["integrity"] = f"error: {e}"

    try:
        if verbose:
            print("[RUNNER] Running statistical analysis...")
        statistical.run_all(captures_dir=captures_dir, results_dir=results_dir)
        status["statistical"] = "ok"
    except FileNotFoundError as e:
        print(f"[RUNNER] WARNING: Statistical analysis skipped -- {e}")
        status["statistical"] = f"skipped: {e}"
    except Exception as e:
        print(f"[RUNNER] ERROR: Statistical analysis failed -- {e}")
        status["statistical"] = f"error: {e}"

    if verbose:
        for module, s in status.items():
            print(f"[RUNNER] {module}: {s}")

    return status


def generate_summary_report(results_dir=DEFAULT_RESULTS):
    """Read the result CSVs and write a human-readable summary_report.txt."""
    results_path = Path(results_dir)
    lines = []

    lines.append("=" * 70)
    lines.append("COVERT DATA TRANSMISSION -- METRICS SUMMARY REPORT")
    lines.append("=" * 70)
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")

    # Performance
    lines.append("-" * 70)
    lines.append("PERFORMANCE SUMMARY")
    lines.append("-" * 70)

    timing_csv = results_path / "perf_channel_timing.csv"
    if timing_csv.exists():
        try:
            timing_df = pd.read_csv(timing_csv)
            for channel in timing_df["channel"].unique():
                ch_df = timing_df[timing_df["channel"] == channel]
                avg_time = ch_df["time_sec"].mean()
                lines.append(f"  {channel:>10s} avg time: {avg_time:.4f} sec")
        except Exception as e:
            lines.append(f"  Error reading timing data: {e}")
    else:
        lines.append("  (no timing data available)")

    throughput_csv = results_path / "perf_throughput.csv"
    if throughput_csv.exists():
        try:
            tp_df = pd.read_csv(throughput_csv)
            lines.append("")
            for channel in tp_df["channel"].unique():
                ch_df = tp_df[tp_df["channel"] == channel]
                avg_tp = ch_df["throughput_bps"].mean()
                lines.append(f"  {channel:>10s} avg throughput: {avg_tp:.2f} bps")
        except Exception as e:
            lines.append(f"  Error reading throughput data: {e}")

    overhead_csv = results_path / "perf_overhead.csv"
    if overhead_csv.exists():
        try:
            oh_df = pd.read_csv(overhead_csv)
            avg_oh = oh_df["overhead_ratio"].mean()
            lines.append(f"\n  MTNS avg overhead ratio: {avg_oh:.2f}x")
        except Exception as e:
            lines.append(f"  Error reading overhead data: {e}")

    success_csv = results_path / "perf_success_rate.csv"
    if success_csv.exists():
        try:
            sr_df = pd.read_csv(success_csv)
            lines.append("")
            for _, row in sr_df.iterrows():
                lines.append(
                    f"  msg_len={int(row['message_length']):>3d}: "
                    f"{int(row['successful_runs'])}/{int(row['total_runs'])} "
                    f"({row['success_rate']:.0%} success)"
                )
        except Exception as e:
            lines.append(f"  Error reading success rate data: {e}")

    lines.append("")

    # Integrity
    lines.append("-" * 70)
    lines.append("INTEGRITY SUMMARY")
    lines.append("-" * 70)

    integrity_csv = results_path / "integrity_results.csv"
    if integrity_csv.exists():
        try:
            integ_df = pd.read_csv(integrity_csv)
            corruption = integ_df[integ_df["test_name"] == "corruption_detection"]
            if not corruption.empty:
                avg_rate = corruption["value"].mean()
                all_pass = (corruption["pass_fail"] == "PASS").all()
                lines.append(f"  Corruption detection rate: {avg_rate:.2%} avg")
                lines.append(f"  All corruption tests: {'PASS' if all_pass else 'FAIL'}")

            threshold = integ_df[integ_df["test_name"] == "threshold_reconstruction"]
            if not threshold.empty:
                all_pass = (threshold["pass_fail"] == "PASS").all()
                lines.append(f"  Threshold reconstruction: {'ALL PASS' if all_pass else 'SOME FAIL'}")

            sub_k = integ_df[integ_df["test_name"] == "threshold_sub_k"]
            if not sub_k.empty:
                all_pass = (sub_k["pass_fail"] == "PASS").all()
                lines.append(f"  Sub-threshold rejection: {'ALL PASS' if all_pass else 'SOME FAIL'}")
        except Exception as e:
            lines.append(f"  Error reading integrity data: {e}")
    else:
        lines.append("  (no integrity data available)")

    lines.append("")

    # Statistical
    lines.append("-" * 70)
    lines.append("STATISTICAL DETECTABILITY SUMMARY")
    lines.append("-" * 70)

    stat_csv = results_path / "statistical_results.csv"
    if stat_csv.exists():
        try:
            stat_df = pd.read_csv(stat_csv)
            lines.append(f"  {'Test':<30s} {'Channel':<8s} {'Statistic':>10s} {'p-value':>10s} {'Verdict':<6s}")
            lines.append("  " + "-" * 66)
            for _, row in stat_df.iterrows():
                p_str = f"{row['p_value']:.4f}" if pd.notna(row.get("p_value")) else "N/A"
                lines.append(
                    f"  {str(row['test_name']):<30s} "
                    f"{str(row['channel']):<8s} "
                    f"{float(row['statistic_value']):>10.4f} "
                    f"{p_str:>10s} "
                    f"{str(row['pass_fail']):<6s}"
                )
        except Exception as e:
            lines.append(f"  Error reading statistical data: {e}")
    else:
        lines.append("  (no statistical data available)")

    lines.append("")

    lines.append("=" * 70)
    lines.append("FILES IN RESULTS DIRECTORY:")
    for f in sorted(results_path.glob("*.csv")):
        lines.append(f"  {f.name}")
    lines.append("=" * 70)

    report_path = results_path / "summary_report.txt"
    report_text = "\n".join(lines) + "\n"
    with open(report_path, "w") as f:
        f.write(report_text)

    print(f"[RUNNER] Summary report written to {report_path}")
    return report_path


def main():
    parser = argparse.ArgumentParser(description="Run all metrics analyses")
    parser.add_argument("--captures-dir", default=DEFAULT_CAPTURES)
    parser.add_argument("--results-dir", default=DEFAULT_RESULTS)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    os.makedirs(args.results_dir, exist_ok=True)
    status = run_all_analyses(args.captures_dir, args.results_dir, args.verbose)
    generate_summary_report(args.results_dir)

    print("\n[RUNNER] Analysis complete.")
    for module, s in status.items():
        print(f"  {module}: {s}")


if __name__ == "__main__":
    main()
