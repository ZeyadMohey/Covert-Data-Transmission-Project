"""Shared constants and seeded helpers. Sender and receiver must agree on these."""

import random

SEED_VALUE = 42

# Shamir's secret sharing
THRESHOLD_K = 4
TOTAL_SHARES_N = 7
PRIME = (2 ** 127) - 1               # Mersenne prime, supports up to 15-byte messages

# Channel split
ARP_SHARES_COUNT = 2
IP_SHARES_COUNT = 5

# MTNS
EVAL_BITS = 4
MTNS_MAX_ITERATIONS = 10000         # max payload attempts per chunk

# Network
SENDER_IP = "192.168.100.3"
RECEIVER_IP = "192.168.100.6"
INTERFACE = "enp0s8"

# Ports
SOURCE_PORT = 12345
DEST_PORT = 54321
ACK_PORT = 9999

# Protocol
SEPARATOR = "|"
HASH_BITS_COUNT = 8


def generate_random_ips(seed, count=256):
    """Deterministic list of 192.168.100.x IPs shared by sender and receiver."""
    rng = random.Random(seed)
    return [f"192.168.100.{rng.randint(1, 254)}" for _ in range(count)]


def generate_48bit_key(rng):
    """Next 48-bit XOR key from a seeded RNG (one per ARP packet)."""
    return rng.getrandbits(48)


# Timeouts. MTNS is slow on VirtualBox (~2 chunks/sec), so a full transmission
# can run 10-15 minutes; keep CHANNEL_TIMEOUT generous for the slowest channel.
CHANNEL_TIMEOUT = 1200
ACK_TIMEOUT = 30
