"""Integrity tests: hash-based corruption detection and threshold reconstruction.

Calls lib/ directly (no capture data needed) and returns structured result dicts.
"""

import random
from pathlib import Path

import pandas as pd

from lib.secret_sharing import split_secret, reconstruct_secret
from lib.hashing import append_hash, verify_and_extract
from lib.config import THRESHOLD_K, TOTAL_SHARES_N, PRIME


def _flip_char(c):
    """Flip a hex char to a different value (for corruption simulation)."""
    if c.isdigit():
        return 'a' if c != 'a' else 'b'
    return '0' if c != '0' else '1'


def test_corruption_detection(messages, num_trials_per_message=20):
    """Corrupt one char of a hashed share's body and confirm it's detected."""
    results = []
    rng = random.Random(42)

    for msg in messages:
        shares = split_secret(msg, THRESHOLD_K, TOTAL_SHARES_N, PRIME)
        hashed_shares = [append_hash(s) for s in shares]

        detected = 0
        trials = num_trials_per_message

        for _ in range(trials):
            hs = rng.choice(hashed_shares)
            # Corrupt within the share body, not the trailing 8 hash chars
            share_body_len = len(hs) - 8
            if share_body_len <= 0:
                continue
            pos = rng.randint(0, share_body_len - 1)
            corrupted = hs[:pos] + _flip_char(hs[pos]) + hs[pos + 1:]
            valid, _ = verify_and_extract(corrupted)
            if not valid:
                detected += 1

        rate = detected / trials if trials > 0 else 0.0
        results.append({
            "test_name": "corruption_detection",
            "message": msg,
            "trials": trials,
            "detected": detected,
            "detection_rate": rate,
            "pass_fail": "PASS" if rate == 1.0 else "FAIL",
        })

    return results


def test_threshold_reconstruction(messages):
    """Reconstruct with k, k+1, and n shares (must pass); k-1 must fail."""
    results = []

    for msg in messages:
        shares = split_secret(msg, THRESHOLD_K, TOTAL_SHARES_N, PRIME)

        try:
            result_msg = reconstruct_secret(shares[:THRESHOLD_K], PRIME)
            success = (result_msg == msg)
        except Exception:
            success = False
        results.append({
            "test_name": "threshold_reconstruction",
            "message": msg,
            "share_count": THRESHOLD_K,
            "success": success,
            "pass_fail": "PASS" if success else "FAIL",
        })

        try:
            result_msg = reconstruct_secret(shares[:THRESHOLD_K + 1], PRIME)
            success = (result_msg == msg)
        except Exception:
            success = False
        results.append({
            "test_name": "threshold_reconstruction",
            "message": msg,
            "share_count": THRESHOLD_K + 1,
            "success": success,
            "pass_fail": "PASS" if success else "FAIL",
        })

        try:
            result_msg = reconstruct_secret(shares, PRIME)
            success = (result_msg == msg)
        except Exception:
            success = False
        results.append({
            "test_name": "threshold_reconstruction",
            "message": msg,
            "share_count": TOTAL_SHARES_N,
            "success": success,
            "pass_fail": "PASS" if success else "FAIL",
        })

        # k-1 shares should not reconstruct
        try:
            reconstruct_secret(shares[:THRESHOLD_K - 1], PRIME)
            results.append({
                "test_name": "threshold_sub_k",
                "message": msg,
                "share_count": THRESHOLD_K - 1,
                "success": False,
                "pass_fail": "FAIL",
            })
        except (ValueError, Exception):
            results.append({
                "test_name": "threshold_sub_k",
                "message": msg,
                "share_count": THRESHOLD_K - 1,
                "success": False,
                "pass_fail": "PASS",
            })

    return results


def run_all(results_dir="metrics/output/results"):
    """Run both integrity tests and write integrity_results.csv."""
    from pathlib import Path

    results_path = Path(results_dir)
    results_path.mkdir(parents=True, exist_ok=True)

    messages = [
        "Hello",
        "Abcde",
        "Attack dawn",
        "Fire at 0600!!!",
        "Move now plz!!!",
    ]

    corruption_results = test_corruption_detection(messages)
    threshold_results = test_threshold_reconstruction(messages)

    all_results = []
    for r in corruption_results:
        all_results.append({
            "test_name": r["test_name"],
            "message": r["message"],
            "metric": "detection_rate",
            "value": r["detection_rate"],
            "pass_fail": r["pass_fail"],
            "details": f"trials={r['trials']}, detected={r['detected']}",
        })
    for r in threshold_results:
        all_results.append({
            "test_name": r["test_name"],
            "message": r["message"],
            "metric": f"reconstruction_k{r['share_count']}",
            "value": 1.0 if r["success"] or r["pass_fail"] == "PASS" else 0.0,
            "pass_fail": r["pass_fail"],
            "details": f"share_count={r['share_count']}, success={r['success']}",
        })

    df = pd.DataFrame(all_results)
    output_file = results_path / "integrity_results.csv"
    df.to_csv(output_file, index=False)

    print(f"[INTEGRITY] Results written to {output_file}")
    return {"corruption": corruption_results, "threshold": threshold_results}
