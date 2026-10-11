"""Tests for lib/config.py constants and utilities."""

import random

from lib.config import (
    SEED_VALUE,
    EVAL_BITS,
    THRESHOLD_K,
    TOTAL_SHARES_N,
    SENDER_IP,
    RECEIVER_IP,
    INTERFACE,
    SEPARATOR,
    SOURCE_PORT,
    DEST_PORT,
    PRIME,
    ARP_SHARES_COUNT,
    IP_SHARES_COUNT,
    ACK_PORT,
    HASH_BITS_COUNT,
    generate_random_ips,
    generate_48bit_key,
)


def test_constants():
    assert SEED_VALUE == 42
    assert EVAL_BITS == 4
    assert THRESHOLD_K == 4
    assert TOTAL_SHARES_N == 7
    assert SENDER_IP == "192.168.100.3"
    assert RECEIVER_IP == "192.168.100.6"
    assert INTERFACE == "enp0s8"
    assert SEPARATOR == "|"
    assert SOURCE_PORT == 12345
    assert DEST_PORT == 54321
    assert PRIME == (2 ** 127) - 1
    assert ARP_SHARES_COUNT == 2
    assert IP_SHARES_COUNT == 5
    assert ACK_PORT == 9999
    assert HASH_BITS_COUNT == 8


def test_random_ips_deterministic():
    ips_a = generate_random_ips(42)
    ips_b = generate_random_ips(42)
    assert ips_a == ips_b
    assert len(ips_a) == 256
    for ip in ips_a:
        parts = ip.split(".")
        assert len(parts) == 4
        assert parts[0] == "192"
        assert parts[1] == "168"
        assert parts[2] == "100"
        x = int(parts[3])
        assert 1 <= x <= 254


def test_random_ips_different_seeds():
    ips_42 = generate_random_ips(42)
    ips_99 = generate_random_ips(99)
    assert ips_42 != ips_99


def test_48bit_key_deterministic():
    rng_a = random.Random(42)
    rng_b = random.Random(42)
    key_a = generate_48bit_key(rng_a)
    key_b = generate_48bit_key(rng_b)
    assert key_a == key_b
    assert 0 <= key_a <= (2 ** 48) - 1


def test_48bit_key_sequence():
    rng_a = random.Random(42)
    rng_b = random.Random(42)
    seq_a = [generate_48bit_key(rng_a) for _ in range(10)]
    seq_b = [generate_48bit_key(rng_b) for _ in range(10)]
    assert seq_a == seq_b
    assert len(set(seq_a)) > 1


def test_ip_shares_count_consistency():
    assert ARP_SHARES_COUNT + IP_SHARES_COUNT == TOTAL_SHARES_N
