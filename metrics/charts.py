"""Chart generation from analysis result CSVs (decoupled from analysis).

Usage:
    python -m metrics.charts [--results-dir DIR] [--charts-dir DIR]
"""

import argparse
import os
from pathlib import Path

import matplotlib
matplotlib.use('Agg')  # headless backend
import matplotlib.pyplot as plt
import pandas as pd

DEFAULT_RESULTS = "metrics/output/results"
DEFAULT_CHARTS = "metrics/output/charts"


def plot_channel_timing(results_dir, charts_dir):
    """Grouped bar chart: ARP vs MTNS time by message size."""
    timing_df = pd.read_csv(os.path.join(results_dir, "perf_channel_timing.csv"))

    df = timing_df[timing_df["channel"].isin(["ARP", "MTNS"])]
    grouped = df.groupby(["message_length", "channel"])["time_sec"].mean().unstack(fill_value=0)

    fig, ax = plt.subplots(figsize=(10, 6))
    grouped.plot(kind="bar", ax=ax, color=["#2196F3", "#FF9800"])
    ax.set_xlabel("Message Length (characters)")
    ax.set_ylabel("Transmission Time (seconds)")
    ax.set_title("Channel Transmission Time by Message Size")
    ax.legend(title="Channel")
    ax.set_xticklabels(ax.get_xticklabels(), rotation=0)
    plt.tight_layout()
    plt.savefig(os.path.join(charts_dir, "channel_timing.png"), dpi=150)
    plt.close()
    print("[CHARTS] Generated: channel_timing.png")


def plot_throughput(results_dir, charts_dir):
    """Grouped bar chart: throughput (bps) by channel and message size."""
    tp_df = pd.read_csv(os.path.join(results_dir, "perf_throughput.csv"))

    grouped = tp_df.groupby(["message_length", "channel"])["throughput_bps"].mean().unstack(fill_value=0)

    fig, ax = plt.subplots(figsize=(10, 6))
    grouped.plot(kind="bar", ax=ax, color=["#2196F3", "#4CAF50", "#FF9800"])
    ax.set_xlabel("Message Length (characters)")
    ax.set_ylabel("Throughput (bits/second)")
    ax.set_title("Channel Throughput by Message Size")
    ax.legend(title="Channel")
    ax.set_xticklabels(ax.get_xticklabels(), rotation=0)
    plt.tight_layout()
    plt.savefig(os.path.join(charts_dir, "throughput.png"), dpi=150)
    plt.close()
    print("[CHARTS] Generated: throughput.png")


def plot_overhead_ratio(results_dir, charts_dir):
    """Bar chart: MTNS overhead ratio by message size."""
    oh_df = pd.read_csv(os.path.join(results_dir, "perf_overhead.csv"))

    grouped = oh_df.groupby("message_length")["overhead_ratio"].mean()

    fig, ax = plt.subplots(figsize=(8, 5))
    grouped.plot(kind="bar", ax=ax, color="#E91E63")
    ax.set_xlabel("Message Length (characters)")
    ax.set_ylabel("Overhead Ratio (total/marked packets)")
    ax.set_title("MTNS Packet Overhead Ratio by Message Size")
    ax.axhline(y=16, color="gray", linestyle="--", alpha=0.7, label="Theoretical 1/16 ratio")
    ax.legend()
    ax.set_xticklabels(ax.get_xticklabels(), rotation=0)
    plt.tight_layout()
    plt.savefig(os.path.join(charts_dir, "overhead_ratio.png"), dpi=150)
    plt.close()
    print("[CHARTS] Generated: overhead_ratio.png")


def plot_statistical_pvalues(results_dir, charts_dir):
    """Horizontal bars of test p-values with the alpha=0.05 line."""
    stat_df = pd.read_csv(os.path.join(results_dir, "statistical_results.csv"))

    pval_df = stat_df.dropna(subset=["p_value"])
    pval_df = pval_df[pval_df["p_value"].apply(lambda x: not pd.isna(x) and str(x).lower() != "nan")]

    if pval_df.empty:
        print("[CHARTS] No p-values to plot for statistical tests")
        return

    labels = [f"{row['test_name']} ({row['channel']})" for _, row in pval_df.iterrows()]
    p_values = pval_df["p_value"].astype(float).values
    colors = ["#4CAF50" if p >= 0.05 else "#F44336" for p in p_values]

    fig, ax = plt.subplots(figsize=(10, max(4, len(labels) * 0.5)))
    y_pos = range(len(labels))
    ax.barh(y_pos, p_values, color=colors, height=0.6)
    ax.axvline(x=0.05, color="red", linestyle="--", linewidth=2, label="alpha = 0.05")
    ax.set_yticks(y_pos)
    ax.set_yticklabels(labels, fontsize=9)
    ax.set_xlabel("p-value")
    ax.set_title("Statistical Detectability Test Results")
    ax.legend(loc="lower right")
    ax.set_xlim(0, max(1.0, max(p_values) * 1.1))
    plt.tight_layout()
    plt.savefig(os.path.join(charts_dir, "statistical_pvalues.png"), dpi=150)
    plt.close()
    print("[CHARTS] Generated: statistical_pvalues.png")


def plot_entropy_comparison(results_dir, charts_dir):
    """Bar chart: per-channel Shannon entropy vs the 8.0-bit maximum."""
    stat_df = pd.read_csv(os.path.join(results_dir, "statistical_results.csv"))
    entropy_df = stat_df[stat_df["test_name"] == "shannon_entropy"]

    if entropy_df.empty:
        print("[CHARTS] No entropy data to plot")
        return

    channels = entropy_df["channel"].values
    entropies = entropy_df["statistic_value"].astype(float).values

    fig, ax = plt.subplots(figsize=(8, 5))
    x_pos = list(range(len(channels)))
    bars = ax.bar(x_pos, entropies, color=["#2196F3", "#FF9800"][:len(channels)], width=0.5)

    ax.axhline(y=8.0, color="green", linestyle="--", linewidth=2, alpha=0.7, label="Theoretical max (8.0)")
    ax.axhline(y=7.5, color="orange", linestyle=":", linewidth=1.5, alpha=0.7, label="PASS threshold (7.5)")

    ax.set_xticks(x_pos)
    ax.set_xticklabels(channels)
    ax.set_ylabel("Shannon Entropy (bits)")
    ax.set_title("Shannon Entropy: Covert Traffic vs Theoretical Maximum")
    ax.set_ylim(0, 8.5)
    ax.legend()

    for bar, val in zip(bars, entropies):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.1,
                f"{val:.2f}", ha="center", fontsize=11, fontweight="bold")

    plt.tight_layout()
    plt.savefig(os.path.join(charts_dir, "entropy_comparison.png"), dpi=150)
    plt.close()
    print("[CHARTS] Generated: entropy_comparison.png")


def generate_all_charts(results_dir=DEFAULT_RESULTS, charts_dir=DEFAULT_CHARTS):
    """Generate every chart, skipping any whose input CSV is missing."""
    os.makedirs(charts_dir, exist_ok=True)
    print(f"[CHARTS] Generating charts from {results_dir} -> {charts_dir}")

    for plot_fn in [plot_channel_timing, plot_throughput, plot_overhead_ratio,
                    plot_statistical_pvalues, plot_entropy_comparison]:
        try:
            plot_fn(results_dir, charts_dir)
        except FileNotFoundError:
            print(f"[CHARTS] Skipping {plot_fn.__name__}: input CSV not found")
        except Exception as e:
            print(f"[CHARTS] Error in {plot_fn.__name__}: {e}")

    print("[CHARTS] Chart generation complete.")


def main():
    parser = argparse.ArgumentParser(description="Generate charts from analysis results")
    parser.add_argument("--results-dir", default=DEFAULT_RESULTS)
    parser.add_argument("--charts-dir", default=DEFAULT_CHARTS)
    args = parser.parse_args()

    generate_all_charts(args.results_dir, args.charts_dir)


if __name__ == "__main__":
    main()
