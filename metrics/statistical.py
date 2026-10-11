"""Statistical detectability tests for captured covert traffic.

Each function takes arrays/DataFrames of captured data and returns a result dict
with a consistent schema. Tests compare against theoretical distributions
(uniform bytes, exponential timing) and report raw p-values plus PASS/FAIL at
alpha=0.05.
"""

import math
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import stats

ALPHA = 0.05


def _result_dict(test_name, channel, statistic_value, p_value, sample_size):
    """Build a result row; PASS when p_value >= ALPHA."""
    if isinstance(p_value, float) and math.isnan(p_value):
        verdict = "N/A"
    else:
        try:
            p_val_float = float(p_value)
            if math.isnan(p_val_float):
                verdict = "N/A"
            else:
                verdict = "PASS" if p_val_float >= ALPHA else "FAIL"
        except (ValueError, TypeError):
            verdict = "N/A"
            p_val_float = float("nan")

    return {
        "test_name": test_name,
        "channel": channel,
        "statistic_value": round(float(statistic_value), 6),
        "p_value": round(float(p_value), 6) if not math.isnan(float(p_value)) else float("nan"),
        "alpha": ALPHA,
        "pass_fail": verdict,
        "sample_size": int(sample_size),
    }


def chi_square_bytes(byte_values, channel):
    """Chi-square goodness-of-fit: byte frequencies vs uniform(0-255)."""
    observed = np.bincount(np.asarray(byte_values, dtype=int), minlength=256)
    stat, p_value = stats.chisquare(observed)
    return _result_dict("chi_square_bytes", channel, stat, p_value, len(byte_values))


def ks_uniform_bytes(byte_values, channel):
    """K-S test of byte values against uniform, normalized to [0, 1]."""
    normalized = np.asarray(byte_values, dtype=float) / 255.0
    result = stats.kstest(normalized, "uniform")
    return _result_dict("ks_uniform_bytes", channel, result.statistic, result.pvalue, len(byte_values))


def ks_exponential_timing(inter_arrival_times, channel):
    """K-S test of inter-arrival times against an exponential fit (scale=mean)."""
    iat = np.asarray(inter_arrival_times, dtype=float)
    mean_iat = np.mean(iat)
    result = stats.kstest(iat, "expon", args=(0, mean_iat))
    return _result_dict("ks_exponential_timing", channel, result.statistic, result.pvalue, len(iat))


def shannon_entropy_bytes(byte_values, channel):
    """Shannon entropy of the byte distribution; PASS if >= 7.5 of max 8.0 bits."""
    counts = np.bincount(np.asarray(byte_values, dtype=int), minlength=256)
    h = stats.entropy(counts, base=2)
    verdict_val = float("nan")
    result = _result_dict("shannon_entropy", channel, h, verdict_val, len(byte_values))
    result["pass_fail"] = "PASS" if h >= 7.5 else "FAIL"
    return result


def serial_correlation(byte_values, channel):
    """Lag-1 serial correlation with a t-test for significance."""
    x = np.asarray(byte_values, dtype=float)
    if len(x) < 3:
        return _result_dict("serial_correlation", channel, 0.0, float("nan"), len(x))
    r = np.corrcoef(x[:-1], x[1:])[0, 1]
    n = len(x)
    if abs(r) >= 1.0:
        p_value = 0.0
    else:
        t_stat = r * math.sqrt(n - 2) / math.sqrt(1 - r ** 2)
        p_value = 2 * (1 - stats.t.cdf(abs(t_stat), df=n - 2))
    return _result_dict("serial_correlation", channel, r, p_value, n)


def runs_test(binary_sequence, channel):
    """Wald-Wolfowitz runs test for randomness in a 0/1 sequence."""
    seq = np.asarray(binary_sequence, dtype=int)
    n = len(seq)
    n1 = int(np.sum(seq == 1))
    n2 = int(np.sum(seq == 0))
    if n1 == 0 or n2 == 0 or n < 2:
        return _result_dict("runs_test", channel, 0.0, float("nan"), n)

    runs = 1 + int(np.sum(seq[1:] != seq[:-1]))

    mu_r = (2 * n1 * n2) / n + 1
    sigma_r_sq = (2 * n1 * n2 * (2 * n1 * n2 - n)) / (n ** 2 * (n - 1))

    if sigma_r_sq <= 0:
        return _result_dict("runs_test", channel, float(runs), float("nan"), n)

    z = (runs - mu_r) / math.sqrt(sigma_r_sq)
    p_value = 2 * (1 - stats.norm.cdf(abs(z)))
    return _result_dict("runs_test", channel, z, p_value, n)


def arp_frequency_analysis(timestamps, channel="ARP"):
    """ARP inter-request gaps: K-S vs exponential plus mean/variance."""
    results = []
    ts = np.asarray(timestamps, dtype=float)
    if len(ts) < 2:
        return results
    gaps = np.diff(ts)

    ks_result = ks_exponential_timing(gaps, channel)
    ks_result["test_name"] = "arp_inter_request_ks_expon"
    results.append(ks_result)

    mean_result = _result_dict("arp_gap_mean", channel, np.mean(gaps), float("nan"), len(gaps))
    mean_result["pass_fail"] = "N/A"
    results.append(mean_result)

    var_result = _result_dict("arp_gap_variance", channel, np.var(gaps), float("nan"), len(gaps))
    var_result["pass_fail"] = "N/A"
    results.append(var_result)

    return results


def tcp_timing_analysis(timestamps, channel="MTNS"):
    """TCP inter-packet gaps: K-S vs exponential plus mean/variance."""
    results = []
    ts = np.asarray(timestamps, dtype=float)
    if len(ts) < 2:
        return results
    gaps = np.diff(ts)

    ks_result = ks_exponential_timing(gaps, channel)
    ks_result["test_name"] = "tcp_inter_packet_ks_expon"
    results.append(ks_result)

    mean_result = _result_dict("tcp_gap_mean", channel, np.mean(gaps), float("nan"), len(gaps))
    mean_result["pass_fail"] = "N/A"
    results.append(mean_result)

    var_result = _result_dict("tcp_gap_variance", channel, np.var(gaps), float("nan"), len(gaps))
    var_result["pass_fail"] = "N/A"
    results.append(var_result)

    return results


def marked_unmarked_ratio(is_marked_flags, channel="MTNS"):
    """Fraction of marked MTNS packets (theoretical ~1/2^eval_bits)."""
    flags = np.asarray(is_marked_flags, dtype=bool)
    total = len(flags)
    marked = int(np.sum(flags))
    ratio = marked / total if total > 0 else 0.0
    result = _result_dict("marked_unmarked_ratio", channel, ratio, float("nan"), total)
    result["pass_fail"] = "N/A"
    return result


def run_all(captures_dir="metrics/output/captures", results_dir="metrics/output/results"):
    """Run every test over the capture CSVs and write statistical_results.csv."""
    captures_path = Path(captures_dir)
    results_path = Path(results_dir)
    results_path.mkdir(parents=True, exist_ok=True)

    all_results = []

    # ARP captures
    arp_csv = captures_path / "arp_captures.csv"
    if arp_csv.exists():
        arp_df = pd.read_csv(arp_csv)

        if "mac_raw" in arp_df.columns:
            mac_bytes = []
            for mac_hex in arp_df["mac_raw"].dropna():
                mac_hex_str = str(mac_hex).replace(":", "").replace("-", "")
                mac_bytes.extend(int(mac_hex_str[i:i + 2], 16) for i in range(0, len(mac_hex_str), 2))
            if mac_bytes:
                all_results.append(chi_square_bytes(np.array(mac_bytes), "ARP"))
                all_results.append(ks_uniform_bytes(np.array(mac_bytes), "ARP"))
                all_results.append(shannon_entropy_bytes(np.array(mac_bytes), "ARP"))
                all_results.append(serial_correlation(np.array(mac_bytes), "ARP"))
                binary_seq = [b >> 7 for b in mac_bytes]
                all_results.append(runs_test(np.array(binary_seq), "ARP"))

        if "timestamp" in arp_df.columns:
            timestamps = arp_df["timestamp"].dropna().values.astype(float)
            all_results.extend(arp_frequency_analysis(timestamps, "ARP"))

    # MTNS captures
    mtns_csv = captures_path / "mtns_captures.csv"
    if mtns_csv.exists():
        mtns_df = pd.read_csv(mtns_csv)

        if "payload_hex" in mtns_df.columns:
            payload_bytes = []
            for payload_hex in mtns_df["payload_hex"].dropna():
                hex_str = str(payload_hex)
                payload_bytes.extend(int(hex_str[i:i + 2], 16) for i in range(0, len(hex_str), 2))
            if payload_bytes:
                all_results.append(chi_square_bytes(np.array(payload_bytes), "MTNS"))
                all_results.append(ks_uniform_bytes(np.array(payload_bytes), "MTNS"))
                all_results.append(shannon_entropy_bytes(np.array(payload_bytes), "MTNS"))
                all_results.append(serial_correlation(np.array(payload_bytes), "MTNS"))
                binary_seq = [b >> 7 for b in payload_bytes]
                all_results.append(runs_test(np.array(binary_seq), "MTNS"))

        if "timestamp" in mtns_df.columns:
            timestamps = mtns_df["timestamp"].dropna().values.astype(float)
            all_results.extend(tcp_timing_analysis(timestamps, "MTNS"))

        # is_marked is stored as "True"/"False" strings (empty for FIN rows);
        # filter to those two and compare so empties aren't read as True.
        if "is_marked" in mtns_df.columns:
            s = mtns_df["is_marked"].astype(str).str.strip().str.lower()
            s = s[s.isin(["true", "false"])]
            if len(s) > 0:
                flags = (s == "true").values
                all_results.append(marked_unmarked_ratio(flags, "MTNS"))

    if all_results:
        results_df = pd.DataFrame(all_results)
        output_file = results_path / "statistical_results.csv"
        results_df.to_csv(output_file, index=False)

    return all_results
