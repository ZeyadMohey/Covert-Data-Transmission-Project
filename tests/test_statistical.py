"""Unit tests for metrics.statistical, using synthetic data."""

import math

import numpy as np
import pytest

from metrics.statistical import (
    arp_frequency_analysis,
    chi_square_bytes,
    ks_exponential_timing,
    ks_uniform_bytes,
    marked_unmarked_ratio,
    run_all,
    runs_test,
    serial_correlation,
    shannon_entropy_bytes,
    tcp_timing_analysis,
)

REQUIRED_KEYS = {
    "test_name",
    "channel",
    "statistic_value",
    "p_value",
    "alpha",
    "pass_fail",
    "sample_size",
}


class TestChiSquareBytes:
    def test_chi_square_uniform(self):
        rng = np.random.RandomState(42)
        data = rng.randint(0, 256, 10000)
        result = chi_square_bytes(data, "ARP")
        assert result["pass_fail"] == "PASS"
        assert result["p_value"] > 0.01
        assert result["test_name"] == "chi_square_bytes"
        assert result["channel"] == "ARP"
        assert result["sample_size"] == 10000

    def test_chi_square_constant(self):
        data = np.zeros(100, dtype=int)
        result = chi_square_bytes(data, "MTNS")
        assert result["pass_fail"] == "FAIL"
        assert result["p_value"] < 0.05


class TestKSTests:
    def test_ks_uniform(self):
        rng = np.random.RandomState(42)
        data = rng.randint(0, 256, 5000)
        result = ks_uniform_bytes(data, "ARP")
        assert result["pass_fail"] == "PASS"
        assert result["p_value"] > 0.01
        assert result["test_name"] == "ks_uniform_bytes"

    def test_ks_exponential(self):
        rng = np.random.RandomState(42)
        data = rng.exponential(1.0, 1000)
        result = ks_exponential_timing(data, "MTNS")
        assert result["pass_fail"] == "PASS"
        assert result["p_value"] > 0.01
        assert result["test_name"] == "ks_exponential_timing"


class TestShannonEntropy:
    def test_entropy_uniform(self):
        rng = np.random.RandomState(42)
        data = rng.randint(0, 256, 10000)
        result = shannon_entropy_bytes(data, "ARP")
        assert result["statistic_value"] > 7.5
        assert result["pass_fail"] == "PASS"
        assert result["test_name"] == "shannon_entropy"

    def test_entropy_constant(self):
        data = np.zeros(100, dtype=int)
        result = shannon_entropy_bytes(data, "MTNS")
        assert result["statistic_value"] < 1.0
        assert result["pass_fail"] == "FAIL"


class TestSerialCorrelation:
    def test_serial_correlation_random(self):
        rng = np.random.RandomState(42)
        data = rng.randint(0, 256, 5000)
        result = serial_correlation(data, "ARP")
        assert abs(result["statistic_value"]) < 0.1
        assert result["test_name"] == "serial_correlation"

    def test_serial_correlation_short(self):
        data = np.array([1, 2])
        result = serial_correlation(data, "ARP")
        assert result["pass_fail"] == "N/A"


class TestRunsTest:
    def test_runs_test_random(self):
        rng = np.random.RandomState(42)
        data = rng.randint(0, 2, 1000)
        result = runs_test(data, "ARP")
        assert result["p_value"] > 0.01
        assert result["test_name"] == "runs_test"

    def test_runs_test_nonrandom(self):
        data = np.array([0] * 500 + [1] * 500)
        result = runs_test(data, "MTNS")
        assert result["p_value"] < 0.05
        assert result["pass_fail"] == "FAIL"


class TestARPFrequency:
    def test_arp_frequency(self):
        rng = np.random.RandomState(42)
        gaps = rng.exponential(0.5, 50)
        timestamps = np.cumsum(gaps)
        results = arp_frequency_analysis(timestamps, "ARP")
        assert isinstance(results, list)
        assert len(results) == 3
        assert "ks" in results[0]["test_name"]

    def test_arp_frequency_too_few(self):
        results = arp_frequency_analysis(np.array([1.0]), "ARP")
        assert results == []


class TestTCPTiming:
    def test_tcp_timing(self):
        rng = np.random.RandomState(42)
        gaps = rng.exponential(0.5, 50)
        timestamps = np.cumsum(gaps)
        results = tcp_timing_analysis(timestamps, "MTNS")
        assert isinstance(results, list)
        assert len(results) == 3
        assert results[0]["channel"] == "MTNS"


class TestMarkedUnmarkedRatio:
    def test_marked_unmarked(self):
        rng = np.random.RandomState(42)
        flags = rng.random(1000) < (1.0 / 16.0)
        result = marked_unmarked_ratio(flags, "MTNS")
        assert abs(result["statistic_value"] - 0.0625) < 0.03
        assert result["test_name"] == "marked_unmarked_ratio"
        assert result["pass_fail"] == "N/A"
        assert result["sample_size"] == 1000


class TestResultSchema:
    def test_all_results_have_required_keys(self):
        rng = np.random.RandomState(42)
        byte_data = rng.randint(0, 256, 1000)
        timing_data = rng.exponential(1.0, 100)
        timestamps = np.cumsum(timing_data)
        binary_data = rng.randint(0, 2, 500)
        flags = rng.random(200) < 0.1

        results = [
            chi_square_bytes(byte_data, "ARP"),
            ks_uniform_bytes(byte_data, "ARP"),
            ks_exponential_timing(timing_data, "MTNS"),
            shannon_entropy_bytes(byte_data, "ARP"),
            serial_correlation(byte_data, "ARP"),
            runs_test(binary_data, "ARP"),
            marked_unmarked_ratio(flags, "MTNS"),
        ]
        results.extend(arp_frequency_analysis(timestamps, "ARP"))
        results.extend(tcp_timing_analysis(timestamps, "MTNS"))

        for r in results:
            missing = REQUIRED_KEYS - set(r.keys())
            assert missing == set(), f"Result {r.get('test_name', '?')} missing keys: {missing}"
            assert isinstance(r["sample_size"], int)
            assert isinstance(r["alpha"], float)
