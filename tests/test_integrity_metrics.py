"""Unit tests for metrics.integrity (corruption detection + threshold reconstruction)."""

import pytest

from metrics.integrity import test_corruption_detection as run_corruption_detection
from metrics.integrity import test_threshold_reconstruction as run_threshold_reconstruction


class TestCorruptionDetection:

    def test_corruption_detection(self):
        results = run_corruption_detection(["Test message"], num_trials_per_message=20)
        assert len(results) > 0
        for r in results:
            assert r["detection_rate"] == 1.0, (
                f"Expected 100% detection, got {r['detection_rate']}"
            )
            assert r["pass_fail"] == "PASS"


class TestThresholdReconstruction:

    def test_threshold_reconstruction(self):
        results = run_threshold_reconstruction(["Hello"])
        k_results = [r for r in results if r["share_count"] == 4]
        assert len(k_results) == 1
        assert k_results[0]["success"] is True
        assert k_results[0]["pass_fail"] == "PASS"

    def test_threshold_k_plus_one(self):
        results = run_threshold_reconstruction(["Hello"])
        kp1_results = [r for r in results if r["share_count"] == 5]
        assert len(kp1_results) == 1
        assert kp1_results[0]["success"] is True

    def test_threshold_all_n(self):
        results = run_threshold_reconstruction(["Hello"])
        n_results = [r for r in results if r["share_count"] == 7]
        assert len(n_results) == 1
        assert n_results[0]["success"] is True

    def test_threshold_below_k(self):
        results = run_threshold_reconstruction(["Hello"])
        below_k = [r for r in results if r["share_count"] == 3]
        assert len(below_k) == 1
        # k-1 shares should raise, which maps to pass_fail='PASS' here
        assert below_k[0]["pass_fail"] == "PASS"


class TestResultSchema:

    def test_corruption_schema(self):
        results = run_corruption_detection(["Hi"], num_trials_per_message=5)
        expected_keys = {"test_name", "message", "trials", "detected", "detection_rate", "pass_fail"}
        for r in results:
            assert expected_keys.issubset(set(r.keys())), (
                f"Missing keys: {expected_keys - set(r.keys())}"
            )

    def test_threshold_schema(self):
        results = run_threshold_reconstruction(["Hi"])
        expected_keys = {"test_name", "message", "share_count", "success", "pass_fail"}
        for r in results:
            assert expected_keys.issubset(set(r.keys())), (
                f"Missing keys: {expected_keys - set(r.keys())}"
            )
