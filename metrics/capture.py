"""VM-side capture: automate transmission runs and save PCAP + per-channel CSVs.

Wraps sender.py / receiver.py via subprocess (stdlib + scapy only).

Usage:
    On receiver VM: sudo python3 -m metrics.capture --role receiver
    On sender VM:   sudo python3 -m metrics.capture --role sender
"""

import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

import argparse
import csv
import os
import subprocess
import sys
import time
from pathlib import Path

# 17 runs. All messages <=15 bytes to stay under the 2^127-1 prime.
TEST_MESSAGES = [
    ("Hello", "short"),
    ("Hello", "short"),
    ("Hello", "short"),
    ("Hello", "short"),
    ("Hello", "short"),
    ("Attack dawn", "medium"),
    ("Attack dawn", "medium"),
    ("Attack dawn", "medium"),
    ("Attack dawn", "medium"),
    ("Attack dawn", "medium"),
    ("Fire at 0600!!!",  "long"),
    ("Fire at 0600!!!",  "long"),
    ("Fire at 0600!!!",  "long"),
    ("Fire at 0600!!!",  "long"),
    ("Fire at 0600!!!",  "long"),
    ("A", "edge_min"),
    ("Move now plz!!!", "edge_max"),
]

CAPTURE_DIR = "metrics/output/captures"


def _ensure_dirs():
    os.makedirs(CAPTURE_DIR, exist_ok=True)


def _extract_arp_csv(packets, output_path):
    """Write ARP-reply MAC fields (index, mac, timestamp) to CSV."""
    from scapy.all import ARP

    rows = []
    idx = 0
    for pkt in packets:
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:
            rows.append({
                "packet_index": idx,
                "mac_raw": pkt[ARP].hwsrc.replace(":", ""),
                "timestamp": float(pkt.time),
            })
            idx += 1

    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["packet_index", "mac_raw", "timestamp"])
        writer.writeheader()
        writer.writerows(rows)

    return rows


def _extract_mtns_csv(packets, output_path):
    """Write TCP packet fields to CSV (is_marked filled in later by analysis)."""
    from scapy.all import TCP, Raw

    rows = []
    idx = 0
    for pkt in packets:
        if pkt.haslayer(TCP):
            payload_hex = ""
            if pkt.haslayer(Raw):
                payload_hex = pkt[Raw].load.hex()
            rows.append({
                "packet_index": idx,
                "payload_hex": payload_hex,
                "timestamp": float(pkt.time),
                "seq_num": pkt[TCP].seq,
                "is_marked": "",
                "tcp_flags": str(pkt[TCP].flags),
            })
            idx += 1

    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=["packet_index", "payload_hex", "timestamp", "seq_num", "is_marked", "tcp_flags"]
        )
        writer.writeheader()
        writer.writerows(rows)

    return rows


def _compute_timing(arp_rows, mtns_rows):
    """Per-channel and total elapsed time from packet timestamps."""
    arp_time = 0.0
    mtns_time = 0.0

    if arp_rows:
        timestamps = [r["timestamp"] for r in arp_rows]
        arp_time = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0.0

    if mtns_rows:
        timestamps = [r["timestamp"] for r in mtns_rows]
        mtns_time = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0.0

    all_ts = [r["timestamp"] for r in arp_rows] + [r["timestamp"] for r in mtns_rows]
    total_time = (max(all_ts) - min(all_ts)) if len(all_ts) > 1 else 0.0

    return {
        "arp_time_sec": round(arp_time, 6),
        "mtns_time_sec": round(mtns_time, 6),
        "total_time_sec": round(total_time, 6),
    }


def _count_mtns_stats(mtns_rows):
    """Count non-FIN MTNS packets and how many were marked."""
    total = 0
    marked = 0
    for row in mtns_rows:
        if "F" in row.get("tcp_flags", ""):
            continue
        total += 1
        if str(row.get("is_marked", "")).lower() == "true":
            marked += 1
    return total, marked


def _populate_is_marked(mtns_csv_path, mtns_rows, seed, eval_bits,
                        sender_ip, receiver_ip, src_port, dst_port):
    """Replay the MTNS marking protocol over captured packets to set is_marked.

    Regenerates the permutation from the shared seed for each data packet (the
    RNG advances once per packet) and reads the hash bit at the last index, the
    same way mtns_receive does live. Rewrites the CSV and mutates mtns_rows.
    """
    import random
    from lib.ip_steg import _generate_permutation, _compute_packet_hash

    rng = random.Random(seed)

    for row in mtns_rows:
        flags = str(row.get("tcp_flags", ""))
        # Only the sender's data packets count; FIN and RST (OS rejecting raw TCP) don't
        if "F" in flags or "R" in flags or row.get("payload_hex", "") in ("", None, "nan"):
            row["is_marked"] = ""
            continue
        permutation = _generate_permutation(rng, eval_bits + 1)
        hash_binary = _compute_packet_hash(
            sender_ip, receiver_ip, src_port, dst_port,
            int(row["seq_num"]), row.get("payload_hex", ""),
        )
        last_bit = hash_binary[permutation[-1]]
        row["is_marked"] = "True" if last_bit == "1" else "False"

    with open(mtns_csv_path, "w", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=["packet_index", "payload_hex", "timestamp", "seq_num", "is_marked", "tcp_flags"]
        )
        writer.writeheader()
        writer.writerows(mtns_rows)


def _check_receiver_success(proc):
    try:
        stdout = proc.stdout if isinstance(proc.stdout, str) else (proc.stdout.decode("utf-8", errors="replace") if proc.stdout else "")
        return "Secret message:" in stdout
    except Exception:
        return False


def run_single_capture(message, run_id, role, output_dir=CAPTURE_DIR, sender_delay=0):
    """Run one sender+receiver transmission, capture packets, return perf row."""
    from scapy.all import AsyncSniffer, wrpcap, ARP, TCP

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from lib.config import SENDER_IP, RECEIVER_IP, INTERFACE, DEST_PORT

    os.makedirs(output_dir, exist_ok=True)

    bpf_filter = f"arp or (tcp and port {DEST_PORT})"
    sniffer = AsyncSniffer(iface=INTERFACE, filter=bpf_filter, store=True)
    sniffer.start()
    time.sleep(0.5)

    success = False
    if role == "sender":
        if sender_delay > 0:
            print(f"[CAPTURE] Waiting {sender_delay}s for receiver to start listening...")
            time.sleep(sender_delay)
        proc = subprocess.Popen(
            [sys.executable, "sender.py"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        # Two newlines: message input, then the "Press Enter" prompt
        stdin_data = f"{message}\n\n".encode()
        stdout_bytes, stderr_bytes = proc.communicate(input=stdin_data, timeout=600)
        success = proc.returncode == 0

    elif role == "receiver":
        proc = subprocess.Popen(
            [sys.executable, "receiver.py"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout_bytes, _ = proc.communicate(timeout=600)
        stdout_text = stdout_bytes.decode("utf-8", errors="replace") if stdout_bytes else ""
        success = "Secret message:" in stdout_text

    sniffer.stop()
    captured_packets = sniffer.results or []

    packet_list = list(captured_packets) if captured_packets else []

    if not packet_list:
        print(f"[CAPTURE] Run {run_id}: No packets captured")
        return None

    pcap_path = os.path.join(output_dir, f"run_{run_id}.pcap")
    wrpcap(pcap_path, packet_list)

    arp_packets = [p for p in packet_list if p.haslayer(ARP) and p[ARP].op == 2]
    tcp_packets = [p for p in packet_list if p.haslayer(TCP)]

    arp_csv_path = os.path.join(output_dir, f"run_{run_id}_arp.csv")
    mtns_csv_path = os.path.join(output_dir, f"run_{run_id}_mtns.csv")

    arp_rows = _extract_arp_csv(packet_list, arp_csv_path)
    mtns_rows = _extract_mtns_csv(packet_list, mtns_csv_path)

    from lib.config import (
        SEED_VALUE, EVAL_BITS, SENDER_IP, RECEIVER_IP, SOURCE_PORT, DEST_PORT,
    )
    _populate_is_marked(
        mtns_csv_path, mtns_rows, SEED_VALUE, EVAL_BITS,
        SENDER_IP, RECEIVER_IP, SOURCE_PORT, DEST_PORT,
    )

    timing = _compute_timing(arp_rows, mtns_rows)
    mtns_total, mtns_marked = _count_mtns_stats(mtns_rows)

    arp_bits = len(arp_rows) * 44   # 11 hex digits = 44 data bits per ARP packet
    mtns_bits = len(message) * 8

    perf_row = {
        "message": message,
        "message_length": len(message),
        "run_number": run_id,
        "arp_time_sec": timing["arp_time_sec"],
        "mtns_time_sec": timing["mtns_time_sec"],
        "total_time_sec": timing["total_time_sec"],
        "arp_bits": arp_bits,
        "mtns_bits": mtns_bits,
        "mtns_total_packets": mtns_total,
        "mtns_marked_packets": mtns_marked,
        "success": success,
    }

    print(f"[CAPTURE] Run {run_id}: {len(packet_list)} packets captured, "
          f"ARP={len(arp_rows)}, TCP={len(mtns_rows)}, success={success}")

    return perf_row


def run_all_captures(role, sender_delay=0):
    """Run all 17 captures (3s between runs) and write a master performance.csv."""
    _ensure_dirs()
    perf_rows = []

    print(f"[CAPTURE] Starting {len(TEST_MESSAGES)} capture runs as {role}")
    print(f"[CAPTURE] Output directory: {CAPTURE_DIR}")

    for i, (message, category) in enumerate(TEST_MESSAGES):
        run_id = f"{i + 1:02d}"
        print(f"\n[CAPTURE] === Run {run_id}/{len(TEST_MESSAGES)} ({category}): "
              f"\"{message[:30]}{'...' if len(message) > 30 else ''}\" ===")

        result = run_single_capture(message, run_id, role, CAPTURE_DIR, sender_delay)
        if result:
            perf_rows.append(result)
        else:
            print(f"[CAPTURE] Run {run_id}: FAILED (no packets captured)")
            perf_rows.append({
                "message": message,
                "message_length": len(message),
                "run_number": run_id,
                "arp_time_sec": 0.0,
                "mtns_time_sec": 0.0,
                "total_time_sec": 0.0,
                "arp_bits": 0,
                "mtns_bits": 0,
                "mtns_total_packets": 0,
                "mtns_marked_packets": 0,
                "success": False,
            })

        if i < len(TEST_MESSAGES) - 1:
            print(f"[CAPTURE] Waiting 3 seconds before next run...")
            time.sleep(3)

    perf_csv_path = os.path.join(CAPTURE_DIR, "performance.csv")
    fieldnames = [
        "message", "message_length", "run_number",
        "arp_time_sec", "mtns_time_sec", "total_time_sec",
        "arp_bits", "mtns_bits",
        "mtns_total_packets", "mtns_marked_packets", "success",
    ]
    with open(perf_csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(perf_rows)

    print(f"\n[CAPTURE] All {len(TEST_MESSAGES)} runs complete.")
    print(f"[CAPTURE] Performance CSV: {perf_csv_path}")
    print(f"[CAPTURE] Successful runs: {sum(1 for r in perf_rows if r['success'])}/{len(perf_rows)}")


def main():
    parser = argparse.ArgumentParser(
        description="Capture metrics data from live transmissions"
    )
    parser.add_argument(
        "--role", choices=["sender", "receiver"], required=True,
        help="Which VM role this script runs on"
    )
    parser.add_argument(
        "--delay", type=int, default=5,
        help="Seconds sender waits before launching sender.py per run (default: 5)"
    )
    args = parser.parse_args()

    _ensure_dirs()
    run_all_captures(args.role, sender_delay=args.delay if args.role == "sender" else 0)


if __name__ == "__main__":
    main()
