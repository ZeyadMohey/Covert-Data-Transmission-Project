"""Tests for metrics/runner.py orchestration and summary report."""

import os
import csv
import tempfile
from pathlib import Path

import pytest


def _write_synthetic_performance_csv(captures_dir):
    """Write a minimal 3-row performance.csv."""
    os.makedirs(captures_dir, exist_ok=True)
    perf_path = os.path.join(captures_dir, "performance.csv")
    fieldnames = [
        "message", "message_length", "run_number",
        "arp_time_sec", "mtns_time_sec", "total_time_sec",
        "arp_bits", "mtns_bits",
        "mtns_total_packets", "mtns_marked_packets", "success",
    ]
    rows = [
        {"message": "Hello", "message_length": 5, "run_number": 1,
         "arp_time_sec": 0.5, "mtns_time_sec": 2.0, "total_time_sec": 2.1,
         "arp_bits": 88, "mtns_bits": 40, "mtns_total_packets": 30,
         "mtns_marked_packets": 10, "success": True},
        {"message": "Hello", "message_length": 5, "run_number": 2,
         "arp_time_sec": 0.6, "mtns_time_sec": 1.8, "total_time_sec": 1.9,
         "arp_bits": 88, "mtns_bits": 40, "mtns_total_packets": 28,
         "mtns_marked_packets": 10, "success": True},
        {"message": "Attack at dawn today", "message_length": 20, "run_number": 1,
         "arp_time_sec": 1.0, "mtns_time_sec": 5.0, "total_time_sec": 5.2,
         "arp_bits": 176, "mtns_bits": 160, "mtns_total_packets": 80,
         "mtns_marked_packets": 40, "success": True},
    ]
    with open(perf_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    return perf_path


def _write_synthetic_result_csvs(results_dir):
    """Write minimal result CSVs for summary-report testing."""
    os.makedirs(results_dir, exist_ok=True)

    with open(os.path.join(results_dir, "perf_channel_timing.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["message_length", "run_number", "channel", "time_sec"])
        writer.writeheader()
        writer.writerow({"message_length": 5, "run_number": 1, "channel": "ARP", "time_sec": 0.5})
        writer.writerow({"message_length": 5, "run_number": 1, "channel": "MTNS", "time_sec": 2.0})

    with open(os.path.join(results_dir, "perf_success_rate.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["message_length", "total_runs", "successful_runs", "success_rate"])
        writer.writeheader()
        writer.writerow({"message_length": 5, "total_runs": 2, "successful_runs": 2, "success_rate": 1.0})

    with open(os.path.join(results_dir, "integrity_results.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["test_name", "message", "metric", "value", "pass_fail", "details"])
        writer.writeheader()
        writer.writerow({
            "test_name": "corruption_detection", "message": "Hello",
            "metric": "detection_rate", "value": 1.0, "pass_fail": "PASS",
            "details": "trials=20, detected=20",
        })

    with open(os.path.join(results_dir, "statistical_results.csv"), "w", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=["test_name", "channel", "statistic_value", "p_value", "alpha", "pass_fail", "sample_size"]
        )
        writer.writeheader()
        writer.writerow({
            "test_name": "chi_square_bytes", "channel": "ARP",
            "statistic_value": 250.0, "p_value": 0.55, "alpha": 0.05,
            "pass_fail": "PASS", "sample_size": 1000,
        })


def test_csv_output():
    from metrics.runner import run_all_analyses

    with tempfile.TemporaryDirectory() as tmpdir:
        captures_dir = os.path.join(tmpdir, "captures")
        results_dir = os.path.join(tmpdir, "results")

        _write_synthetic_performance_csv(captures_dir)

        status = run_all_analyses(captures_dir=captures_dir, results_dir=results_dir)

        result_files = list(Path(results_dir).glob("*.csv"))
        assert len(result_files) >= 1, f"Expected at least 1 result CSV, got {len(result_files)}"

        assert isinstance(status, dict)
        assert "performance" in status


def test_summary_report():
    from metrics.runner import generate_summary_report

    with tempfile.TemporaryDirectory() as tmpdir:
        results_dir = tmpdir
        _write_synthetic_result_csvs(results_dir)

        generate_summary_report(results_dir=results_dir)

        report_path = os.path.join(results_dir, "summary_report.txt")
        assert os.path.exists(report_path), "summary_report.txt not created"

        with open(report_path, "r") as f:
            content = f.read()

        assert "SUMMARY REPORT" in content or "Summary Report" in content
        content_upper = content.upper()
        assert "PERFORMANCE" in content_upper
        assert "INTEGRITY" in content_upper
        assert "STATISTICAL" in content_upper


def test_missing_captures_graceful():
    from metrics.runner import run_all_analyses

    with tempfile.TemporaryDirectory() as tmpdir:
        captures_dir = os.path.join(tmpdir, "empty_captures")
        results_dir = os.path.join(tmpdir, "results")
        os.makedirs(captures_dir, exist_ok=True)

        status = run_all_analyses(captures_dir=captures_dir, results_dir=results_dir)
        assert isinstance(status, dict)
        assert "performance" in status


def test_runner_cli_args():
    import argparse
    from metrics.runner import main

    import metrics.runner as runner_module
    assert hasattr(runner_module, "main")
    assert hasattr(runner_module, "run_all_analyses")
    assert hasattr(runner_module, "generate_summary_report")
    assert hasattr(runner_module, "DEFAULT_CAPTURES")
    assert hasattr(runner_module, "DEFAULT_RESULTS")
