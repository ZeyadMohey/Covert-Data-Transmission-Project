"""Combine per-run capture CSVs into aggregate files for statistical analysis.

Run after copying captures off the VM, before metrics.runner. Also re-derives
is_marked per run, since RST+ACK packets on the VM corrupt the captured values.

Usage:
    python -m metrics.aggregate
"""

import random
import pandas as pd
from pathlib import Path

from lib.ip_steg import _generate_permutation, _compute_packet_hash
from lib.config import SEED_VALUE, EVAL_BITS, SENDER_IP, RECEIVER_IP, SOURCE_PORT, DEST_PORT

CAPTURES_DIR = Path("metrics/output/captures")


def _fix_is_marked(df):
    """Re-derive is_marked for one run by replaying the marking protocol.

    One permutation per chunk; it only advances when a marked packet (check
    bit 1) is found. RST+ACK packets are OS responses, not part of the stream,
    so they're excluded without consuming a permutation.
    """
    rng = random.Random(SEED_VALUE)
    permutation = _generate_permutation(rng, EVAL_BITS + 1)
    result = df.copy()

    for idx, row in result.iterrows():
        flags = str(row.get("tcp_flags", ""))
        payload = str(row.get("payload_hex", ""))

        # Skip FIN, RST+ACK, and empty-payload packets entirely
        if "F" in flags or "R" in flags or payload in ("", "nan", "None"):
            result.at[idx, "is_marked"] = ""
            continue

        hash_binary = _compute_packet_hash(
            SENDER_IP, RECEIVER_IP, SOURCE_PORT, DEST_PORT,
            int(row["seq_num"]), payload,
        )
        last_bit = hash_binary[permutation[-1]]
        if last_bit == "1":
            result.at[idx, "is_marked"] = "True"
            # Chunk complete — advance to next permutation
            permutation = _generate_permutation(rng, EVAL_BITS + 1)
        else:
            result.at[idx, "is_marked"] = "False"
            # Same permutation used for next packet in this chunk

    return result


def aggregate():
    if not CAPTURES_DIR.exists():
        print(f"[AGGREGATE] ERROR: {CAPTURES_DIR} does not exist. Transfer VM captures first.")
        return

    # ARP
    arp_files = sorted(CAPTURES_DIR.glob("run_*_arp.csv"))
    if arp_files:
        arp_df = pd.concat([pd.read_csv(f) for f in arp_files], ignore_index=True)
        arp_df.to_csv(CAPTURES_DIR / "arp_captures.csv", index=False)
        print(f"[AGGREGATE] arp_captures.csv: {len(arp_df)} rows from {len(arp_files)} files")
    else:
        print("[AGGREGATE] WARNING: No run_*_arp.csv files found")

    # MTNS — fix is_marked per run before aggregating
    mtns_files = sorted(CAPTURES_DIR.glob("run_*_mtns.csv"))
    if mtns_files:
        fixed_frames = []
        for f in mtns_files:
            df = pd.read_csv(f)
            fixed_frames.append(_fix_is_marked(df))
        mtns_df = pd.concat(fixed_frames, ignore_index=True)
        mtns_df.to_csv(CAPTURES_DIR / "mtns_captures.csv", index=False)

        # Report new marked ratio
        s = mtns_df["is_marked"].astype(str).str.strip().str.lower()
        s = s[s.isin(["true", "false"])]
        marked = (s == "true").sum()
        total = len(s)
        ratio = marked / total if total > 0 else 0.0
        print(f"[AGGREGATE] mtns_captures.csv: {len(mtns_df)} rows from {len(mtns_files)} files")
        print(f"[AGGREGATE] marked_unmarked_ratio: {marked}/{total} = {ratio:.4f} "
              f"(theoretical ~0.0625 for eval_bits=4)")
    else:
        print("[AGGREGATE] WARNING: No run_*_mtns.csv files found")

    print("[AGGREGATE] Done. Run: python -m metrics.runner --verbose")


if __name__ == "__main__":
    aggregate()
