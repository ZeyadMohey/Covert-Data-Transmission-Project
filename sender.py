"""Sender: split a message into shares and push them over both covert channels."""

# Quiet down scapy/cryptography import noise
import warnings
warnings.filterwarnings("ignore", message=".*Python 3.8 is no longer supported.*")
warnings.filterwarnings("ignore", message=".*'iface' has no effect on L3.*")
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=SyntaxWarning)

import multiprocessing
import multiprocessing.queues
import time
import sys

from lib.config import (
    SEED_VALUE, THRESHOLD_K, TOTAL_SHARES_N, PRIME,
    ARP_SHARES_COUNT, EVAL_BITS, SENDER_IP, RECEIVER_IP,
    INTERFACE, SOURCE_PORT, DEST_PORT, ACK_PORT, SEPARATOR,
    CHANNEL_TIMEOUT, ACK_TIMEOUT,
)
from lib.secret_sharing import split_secret
from lib.hashing import append_hash
from lib.arp_steg import arp_send
from lib.ip_steg import mtns_send


def _channel_worker(target_func, args, result_queue, channel_name):
    """Run a channel send in a subprocess, reporting ok/error via the queue."""
    try:
        result = target_func(*args)
        result_queue.put(("ok", channel_name, result))
    except Exception as e:
        result_queue.put(("error", channel_name, str(e)))


def _sniff_ack(receiver_ip, ack_port, interface, timeout):
    """Sniff for the receiver's ACK (split out for testability)."""
    from scapy.all import sniff
    return sniff(
        filter=f"tcp and src host {receiver_ip} and dst port {ack_port}",
        iface=interface,
        count=1,
        timeout=timeout,
    )


def _ack_listener(ack_queue, receiver_ip, ack_port, interface, timeout):
    packets = _sniff_ack(receiver_ip, ack_port, interface, timeout)
    if packets:
        ack_queue.put(True)
    else:
        ack_queue.put(False)


def main():
    print("[SENDER] Covert Data Transmission System")

    message = input("[SENDER] Enter secret message: ")
    if not message:
        print("[SENDER] ERROR: Message cannot be empty.")
        sys.exit(1)

    print(f"[SENDER] Secret message: {message}")

    print(f"[SENDER] Generating {TOTAL_SHARES_N} shares with threshold {THRESHOLD_K}...")
    shares = split_secret(message, THRESHOLD_K, TOTAL_SHARES_N, PRIME)
    for i, share in enumerate(shares):
        print(f"[SENDER] Share {i + 1}: {share}")

    print("[SENDER] Hashing shares for integrity...")
    hashed_shares = [append_hash(s) for s in shares]
    for i, hs in enumerate(hashed_shares):
        print(f"[SENDER] Hashed Share {i + 1}: {hs}")

    arp_shares = hashed_shares[:ARP_SHARES_COUNT]
    mtns_shares = hashed_shares[ARP_SHARES_COUNT:]
    arp_data = SEPARATOR.join(arp_shares)
    mtns_data = SEPARATOR.join(mtns_shares)

    print(f"[SENDER] Sending {len(arp_shares)} shares via ARP channel...")
    print(f"[SENDER] Sending {len(mtns_shares)} shares via MTNS channel...")

    # Start the ACK listener before transmitting so we can't miss it
    ack_q = multiprocessing.Queue()
    ack_proc = multiprocessing.Process(
        target=_ack_listener,
        args=(ack_q, RECEIVER_IP, ACK_PORT, INTERFACE, ACK_TIMEOUT + CHANNEL_TIMEOUT),
    )
    ack_proc.start()

    input("[SENDER] Press Enter to begin transmission...")

    start_time = time.time()

    # Both channels transmit in parallel
    q = multiprocessing.Queue()
    arp_proc = multiprocessing.Process(
        target=_channel_worker,
        args=(arp_send, (arp_data, SEED_VALUE, SENDER_IP, RECEIVER_IP, INTERFACE), q, "ARP"),
    )
    mtns_proc = multiprocessing.Process(
        target=_channel_worker,
        args=(
            mtns_send,
            (mtns_data, SEED_VALUE, EVAL_BITS, SENDER_IP, RECEIVER_IP, SOURCE_PORT, DEST_PORT, INTERFACE),
            q,
            "MTNS",
        ),
    )
    arp_proc.start()
    mtns_proc.start()

    arp_proc.join(timeout=CHANNEL_TIMEOUT)
    mtns_proc.join(timeout=CHANNEL_TIMEOUT)

    results_collected = 0
    while results_collected < 2:
        try:
            status, name, payload = q.get(timeout=5)
            if status == "ok":
                print(f"[SENDER] {name} channel: transmission complete")
            else:
                print(f"[SENDER] WARNING: {name} channel failed: {payload}")
            results_collected += 1
        except multiprocessing.queues.Empty:
            break

    for proc in [arp_proc, mtns_proc]:
        if proc.is_alive():
            print("[SENDER] WARNING: Channel process timed out, terminating...")
            proc.terminate()
            proc.join(timeout=5)

    try:
        ack_received = ack_q.get(timeout=ACK_TIMEOUT)
    except multiprocessing.queues.Empty:
        ack_received = False

    ack_proc.join(timeout=5)
    if ack_proc.is_alive():
        ack_proc.terminate()
        ack_proc.join(timeout=5)

    if ack_received:
        print("[SENDER] ACK received! Transmission successful.")
    else:
        print("[SENDER] No ACK received. Transmission may have failed.")

    elapsed = time.time() - start_time
    print(f"[SENDER] Total time: {elapsed:.2f} seconds")


if __name__ == "__main__":
    main()
