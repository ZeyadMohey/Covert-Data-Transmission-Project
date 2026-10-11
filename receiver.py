"""Receiver: pull shares off both channels, verify integrity, rebuild the message.

Usage (on receiver VM): sudo python3 receiver.py
"""

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
    SEED_VALUE, THRESHOLD_K, PRIME,
    ARP_SHARES_COUNT, EVAL_BITS, SENDER_IP, RECEIVER_IP,
    INTERFACE, SOURCE_PORT, DEST_PORT, ACK_PORT, SEPARATOR,
)
from lib.secret_sharing import reconstruct_secret
from lib.hashing import verify_and_extract
from lib.arp_steg import arp_receive
from lib.ip_steg import mtns_receive

try:
    from lib.config import CHANNEL_TIMEOUT, ACK_TIMEOUT
except ImportError:
    CHANNEL_TIMEOUT = 120
    ACK_TIMEOUT = 30

# Module-level so tests can patch them; real network calls live in _send_ack
try:
    from scapy.all import IP, TCP, Raw, send
except ImportError:
    IP = None
    TCP = None
    Raw = None
    send = None


def _receiver_channel_worker(ready_event, target_func, args, result_queue, channel_name):
    """Run a channel receive in a subprocess, signalling readiness first."""
    ready_event.set()
    try:
        result = target_func(*args)
        result_queue.put(("ok", channel_name, result))
    except Exception as e:
        result_queue.put(("error", channel_name, str(e)))


def _send_ack(sender_ip, receiver_ip, ack_port, interface):
    """Send a TCP ACK packet back to the sender."""
    pkt = IP(src=receiver_ip, dst=sender_ip) / TCP(
        sport=ack_port, dport=ack_port, flags="A"
    ) / Raw(load=b"ACK")
    send(pkt, iface=interface, verbose=False)


def _validate_shares(tagged_shares):
    """Verify each (channel, hashed_share); return (valid, invalid) lists."""
    valid_shares = []
    invalid_shares = []

    for channel, hashed_share in tagged_shares:
        ok, original = verify_and_extract(hashed_share)
        if ok:
            valid_shares.append((channel, original))
            print(f"[RECEIVER] Share from {channel}: {hashed_share[:20]}... -> VALID")
        else:
            invalid_shares.append((channel, hashed_share))
            print(f"[RECEIVER] Share from {channel}: {hashed_share[:20]}... -> INVALID (discarded)")

    arp_valid = sum(1 for ch, _ in valid_shares if ch == "ARP")
    mtns_valid = sum(1 for ch, _ in valid_shares if ch == "MTNS")
    print(f"[RECEIVER] Valid shares: {arp_valid} from ARP, {mtns_valid} from MTNS ({len(valid_shares)} total)")

    return valid_shares, invalid_shares


def _attempt_reconstruction(valid_shares, invalid_shares, results, threshold_k, prime):
    """Reconstruct the message if enough shares are valid; ACK on success."""
    if len(valid_shares) >= threshold_k:
        share_strings = [s for _, s in valid_shares]
        print(f"[RECEIVER] Reconstructing message with {len(valid_shares)} shares...")
        message = reconstruct_secret(share_strings, prime)
        print(f"[RECEIVER] Secret message: {message}")

        print("[RECEIVER] Sending ACK to sender...")
        try:
            _send_ack(SENDER_IP, RECEIVER_IP, ACK_PORT, INTERFACE)
            print("[RECEIVER] ACK sent successfully.")
        except Exception as e:
            print(f"[RECEIVER] WARNING: Failed to send ACK: {e}")

        return message
    else:
        arp_valid = sum(1 for ch, _ in valid_shares if ch == "ARP")
        mtns_valid = sum(1 for ch, _ in valid_shares if ch == "MTNS")
        print(f"[RECEIVER] FAILED: Not enough valid shares (got {len(valid_shares)}, need {threshold_k})")
        print("[RECEIVER] Diagnostics:")
        print(f"[RECEIVER]   Shares received: {len(valid_shares) + len(invalid_shares)}")
        print(f"[RECEIVER]   Valid: {len(valid_shares)} (ARP: {arp_valid}, MTNS: {mtns_valid})")
        print(f"[RECEIVER]   Invalid: {len(invalid_shares)}")
        for ch, hs in invalid_shares:
            print(f"[RECEIVER]     - {ch}: {hs[:30]}...")
        if "ARP" not in results or results.get("ARP", (None,))[0] == "error":
            print("[RECEIVER]   ARP channel: FAILED")
        if "MTNS" not in results or results.get("MTNS", (None,))[0] == "error":
            print("[RECEIVER]   MTNS channel: FAILED")
        return None


def main():
    print("[RECEIVER] Covert Data Transmission System - Receiver")
    start_time = time.time()

    arp_ready = multiprocessing.Event()
    mtns_ready = multiprocessing.Event()
    result_q = multiprocessing.Queue()

    arp_proc = multiprocessing.Process(
        target=_receiver_channel_worker,
        args=(arp_ready, arp_receive,
              (SEED_VALUE, SENDER_IP, RECEIVER_IP, INTERFACE),
              result_q, "ARP"),
    )
    mtns_proc = multiprocessing.Process(
        target=_receiver_channel_worker,
        args=(mtns_ready, mtns_receive,
              (SEED_VALUE, EVAL_BITS, SENDER_IP, RECEIVER_IP,
               SOURCE_PORT, DEST_PORT, INTERFACE),
              result_q, "MTNS"),
    )
    arp_proc.start()
    mtns_proc.start()

    # Wait until both sniffers are up before telling the user to start the sender
    arp_ready.wait(timeout=10)
    mtns_ready.wait(timeout=10)
    print("[RECEIVER] Listening on ARP and MTNS channels... Start sender now.")

    arp_proc.join(timeout=CHANNEL_TIMEOUT)
    mtns_proc.join(timeout=CHANNEL_TIMEOUT)

    for name, proc in [("ARP", arp_proc), ("MTNS", mtns_proc)]:
        if proc.is_alive():
            print(f"[RECEIVER] WARNING: {name} channel timed out, terminating...")
            proc.terminate()
            proc.join(timeout=5)

    results = {}
    while not result_q.empty():
        try:
            status, channel, data = result_q.get_nowait()
            results[channel] = (status, data)
        except multiprocessing.queues.Empty:
            break

    arp_data = None
    mtns_data = None
    for channel in ["ARP", "MTNS"]:
        if channel in results:
            status, data = results[channel]
            if status == "ok":
                print(f"[RECEIVER] {channel} channel: received data")
                if channel == "ARP":
                    arp_data = data
                else:
                    mtns_data = data
            else:
                print(f"[RECEIVER] WARNING: {channel} channel failed: {data}")
        else:
            print(f"[RECEIVER] WARNING: {channel} channel: no response (timeout)")

    tagged_shares = []
    if arp_data:
        for s in arp_data.split(SEPARATOR):
            if s:
                tagged_shares.append(("ARP", s))
    if mtns_data:
        for s in mtns_data.split(SEPARATOR):
            if s:
                tagged_shares.append(("MTNS", s))
    print(f"[RECEIVER] Extracted {len(tagged_shares)} hashed shares")

    valid_shares, invalid_shares = _validate_shares(tagged_shares)
    _attempt_reconstruction(valid_shares, invalid_shares, results, THRESHOLD_K, PRIME)

    elapsed = time.time() - start_time
    print(f"[RECEIVER] Total time: {elapsed:.2f} seconds")


if __name__ == "__main__":
    main()
