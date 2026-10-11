"""Performance analysis: timing, throughput, MTNS overhead, and success rate.

Each function takes a capture-schema DataFrame and returns a result DataFrame.
"""

import pandas as pd
import numpy as np
from pathlib import Path


RESULTS_SCHEMA = [
    "message", "message_length", "run_number",
    "metric_name", "channel", "value", "unit",
]


def _ensure_output_dirs():
    for sub in ["captures", "results", "charts"]:
        Path(f"metrics/output/{sub}").mkdir(parents=True, exist_ok=True)


def analyze_channel_timing(perf_df):
    """One row each for ARP, MTNS, and combined transmission time per run."""
    rows = []
    for _, row in perf_df.iterrows():
        base = {
            "message_length": row["message_length"],
            "run_number": row["run_number"],
        }
        rows.append({**base, "channel": "ARP", "time_sec": row["arp_time_sec"]})
        rows.append({**base, "channel": "MTNS", "time_sec": row["mtns_time_sec"]})
        rows.append({**base, "channel": "combined", "time_sec": row["total_time_sec"]})
    return pd.DataFrame(rows)


def analyze_throughput(perf_df):
    """Bits/second per channel (and combined) per run."""
    rows = []
    for _, row in perf_df.iterrows():
        base = {
            "message_length": row["message_length"],
            "run_number": row["run_number"],
        }
        arp_bps = row["arp_bits"] / row["arp_time_sec"] if row["arp_time_sec"] > 0 else 0.0
        mtns_bps = row["mtns_bits"] / row["mtns_time_sec"] if row["mtns_time_sec"] > 0 else 0.0
        combined_bps = (
            (row["arp_bits"] + row["mtns_bits"]) / row["total_time_sec"]
            if row["total_time_sec"] > 0 else 0.0
        )
        rows.append({**base, "channel": "ARP", "throughput_bps": arp_bps})
        rows.append({**base, "channel": "MTNS", "throughput_bps": mtns_bps})
        rows.append({**base, "channel": "combined", "throughput_bps": combined_bps})
    return pd.DataFrame(rows)


def analyze_overhead_ratio(perf_df):
    """MTNS total/marked packet ratio per run (higher = more decoy packets)."""
    rows = []
    for _, row in perf_df.iterrows():
        marked = row["mtns_marked_packets"]
        total = row["mtns_total_packets"]
        ratio = total / marked if marked > 0 else float("inf")
        rows.append({
            "message_length": row["message_length"],
            "run_number": row["run_number"],
            "overhead_ratio": ratio,
            "total_packets": total,
            "marked_packets": marked,
        })
    return pd.DataFrame(rows)


def analyze_success_rate(perf_df):
    """Success rate grouped by message length."""
    grouped = perf_df.groupby("message_length")["success"]
    result = grouped.agg(
        total_runs="count",
        successful_runs="sum",
    ).reset_index()
    result["success_rate"] = result["successful_runs"] / result["total_runs"]
    return result


def run_all(captures_dir="metrics/output/captures", results_dir="metrics/output/results"):
    """Run all performance analyses over performance.csv and write the perf_*.csv files."""
    _ensure_output_dirs()
    results_path = Path(results_dir)
    results_path.mkdir(parents=True, exist_ok=True)

    perf_csv = Path(captures_dir) / "performance.csv"
    perf_df = pd.read_csv(perf_csv)

    timing_df = analyze_channel_timing(perf_df)
    timing_df.to_csv(results_path / "perf_channel_timing.csv", index=False)

    throughput_df = analyze_throughput(perf_df)
    throughput_df.to_csv(results_path / "perf_throughput.csv", index=False)

    overhead_df = analyze_overhead_ratio(perf_df)
    overhead_df.to_csv(results_path / "perf_overhead.csv", index=False)

    success_df = analyze_success_rate(perf_df)
    success_df.to_csv(results_path / "perf_success_rate.csv", index=False)

    print(f"[PERFORMANCE] Results written to {results_path}/")
    return {
        "timing": timing_df,
        "throughput": throughput_df,
        "overhead": overhead_df,
        "success_rate": success_df,
    }
