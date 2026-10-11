"""Unit tests for metrics.performance, using synthetic DataFrames."""

import pandas as pd
import pytest

from metrics.performance import (
    analyze_channel_timing,
    analyze_overhead_ratio,
    analyze_success_rate,
    analyze_throughput,
)


@pytest.fixture
def perf_df():
    return pd.DataFrame({
        "message": ["Hello"] * 3,
        "message_length": [5] * 3,
        "run_number": [1, 2, 3],
        "arp_time_sec": [2.5, 2.8, 2.6],
        "mtns_time_sec": [15.0, 14.5, 16.2],
        "total_time_sec": [15.0, 14.5, 16.2],
        "arp_bits": [440, 440, 440],
        "mtns_bits": [1100, 1100, 1100],
        "mtns_total_packets": [500, 480, 520],
        "mtns_marked_packets": [30, 28, 32],
        "success": [True, True, True],
    })


class TestChannelTiming:

    def test_channel_timing(self, perf_df):
        result = analyze_channel_timing(perf_df)
        assert len(result) == 9, f"Expected 9 rows, got {len(result)}"
        assert set(result["channel"].unique()) == {"ARP", "MTNS", "combined"}
        assert (result["time_sec"] > 0).all()

    def test_total_time(self, perf_df):
        result = analyze_channel_timing(perf_df)
        combined = result[result["channel"] == "combined"].sort_values("run_number")
        expected = [15.0, 14.5, 16.2]
        actual = combined["time_sec"].tolist()
        assert actual == expected, f"Expected {expected}, got {actual}"


class TestThroughput:

    def test_throughput(self, perf_df):
        result = analyze_throughput(perf_df)
        # ARP run 1: 440 / 2.5 = 176.0
        arp_run1 = result[
            (result["channel"] == "ARP") & (result["run_number"] == 1)
        ]
        assert len(arp_run1) == 1
        assert abs(arp_run1["throughput_bps"].iloc[0] - 176.0) < 0.01

        # MTNS run 1: 1100 / 15.0 = 73.333
        mtns_run1 = result[
            (result["channel"] == "MTNS") & (result["run_number"] == 1)
        ]
        assert abs(mtns_run1["throughput_bps"].iloc[0] - 73.333) < 0.01

        # combined run 1: (440+1100) / 15.0 = 102.667
        combined_run1 = result[
            (result["channel"] == "combined") & (result["run_number"] == 1)
        ]
        assert abs(combined_run1["throughput_bps"].iloc[0] - 102.667) < 0.01


class TestOverheadRatio:

    def test_overhead_ratio(self, perf_df):
        result = analyze_overhead_ratio(perf_df)
        assert len(result) == 3
        # run 1: 500 / 30 = 16.667
        row1 = result[result["run_number"] == 1]
        assert abs(row1["overhead_ratio"].iloc[0] - 16.667) < 0.01
        # run 2: 480 / 28 = 17.143
        row2 = result[result["run_number"] == 2]
        assert abs(row2["overhead_ratio"].iloc[0] - 17.143) < 0.01


class TestSuccessRate:

    def test_success_rate(self, perf_df):
        result = analyze_success_rate(perf_df)
        assert len(result) == 1
        assert result["success_rate"].iloc[0] == 1.0
        assert result["total_runs"].iloc[0] == 3
        assert result["successful_runs"].iloc[0] == 3

    def test_success_rate_partial(self):
        df = pd.DataFrame({
            "message": ["A", "A", "A", "A"],
            "message_length": [1, 1, 1, 1],
            "run_number": [1, 2, 3, 4],
            "arp_time_sec": [1.0] * 4,
            "mtns_time_sec": [5.0] * 4,
            "total_time_sec": [5.0] * 4,
            "arp_bits": [100] * 4,
            "mtns_bits": [200] * 4,
            "mtns_total_packets": [100] * 4,
            "mtns_marked_packets": [10] * 4,
            "success": [True, True, False, True],
        })
        result = analyze_success_rate(df)
        assert result["success_rate"].iloc[0] == 0.75
