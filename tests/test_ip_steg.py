"""Unit tests for MTNS steganography helpers."""

import random

import pytest

from lib.ip_steg import (
    _binary_to_hex,
    _check_marking,
    _compute_packet_hash,
    _generate_permutation,
    _hex_decode,
    _hex_encode,
    _hex_to_binary,
)


class TestHexToBinary:

    def test_hex_to_binary_0a(self):
        assert _hex_to_binary("0a") == "00001010"

    def test_hex_to_binary_ff(self):
        assert _hex_to_binary("ff") == "11111111"

    def test_hex_to_binary_0000(self):
        assert _hex_to_binary("0000") == "0000000000000000"

    def test_hex_to_binary_single_digit(self):
        assert _hex_to_binary("1") == "0001"

    def test_hex_to_binary_all_zeros(self):
        assert _hex_to_binary("00") == "00000000"

    def test_hex_to_binary_deadbeef(self):
        result = _hex_to_binary("deadbeef")
        assert len(result) == 32
        assert all(c in "01" for c in result)


class TestBinaryToHex:

    def test_binary_to_hex_0a(self):
        assert _binary_to_hex("00001010") == "0a"

    def test_binary_to_hex_ff(self):
        assert _binary_to_hex("11111111") == "ff"

    def test_binary_to_hex_single_digit(self):
        assert _binary_to_hex("0001") == "1"


class TestHexBinaryRoundtrip:

    @pytest.mark.parametrize("hex_str", ["0a", "ff", "00", "deadbeef", "1", "0000"])
    def test_roundtrip(self, hex_str):
        assert _binary_to_hex(_hex_to_binary(hex_str)) == hex_str


class TestGeneratePermutation:

    def test_correct_length(self):
        rng = random.Random(42)
        result = _generate_permutation(rng, 5)
        assert len(result) == 5

    def test_values_in_range(self):
        rng = random.Random(42)
        result = _generate_permutation(rng, 5)
        for v in result:
            assert 0 <= v <= 255

    def test_deterministic_same_seed(self):
        rng1 = random.Random(42)
        rng2 = random.Random(42)
        assert _generate_permutation(rng1, 5) == _generate_permutation(rng2, 5)

    def test_different_seed_different_result(self):
        rng1 = random.Random(42)
        rng2 = random.Random(99)
        assert _generate_permutation(rng1, 5) != _generate_permutation(rng2, 5)


class TestComputePacketHash:

    def test_returns_256_bit_string(self):
        result = _compute_packet_hash(
            "192.168.100.3", "192.168.100.6", 12345, 54321, 1, "abcdef"
        )
        assert len(result) == 256

    def test_only_binary_chars(self):
        result = _compute_packet_hash(
            "192.168.100.3", "192.168.100.6", 12345, 54321, 1, "abcdef"
        )
        assert all(c in "01" for c in result)

    def test_deterministic(self):
        args = ("192.168.100.3", "192.168.100.6", 12345, 54321, 1, "abcdef")
        assert _compute_packet_hash(*args) == _compute_packet_hash(*args)

    def test_different_seq_num(self):
        h1 = _compute_packet_hash(
            "192.168.100.3", "192.168.100.6", 12345, 54321, 1, "abcdef"
        )
        h2 = _compute_packet_hash(
            "192.168.100.3", "192.168.100.6", 12345, 54321, 2, "abcdef"
        )
        assert h1 != h2

    def test_different_payload(self):
        h1 = _compute_packet_hash(
            "192.168.100.3", "192.168.100.6", 12345, 54321, 1, "abcdef"
        )
        h2 = _compute_packet_hash(
            "192.168.100.3", "192.168.100.6", 12345, 54321, 1, "123456"
        )
        assert h1 != h2


class TestCheckMarking:

    def _make_hash_binary(self, bit_map):
        """Build a 256-bit string with specific indices set."""
        bits = list("0" * 256)
        for idx, val in bit_map.items():
            bits[idx] = val
        return "".join(bits)

    def test_marked_when_bits_match_and_check_1(self):
        # perm = data indices [10,20,30,40] + check index 50; data "1010" matches, check=1
        hash_binary = self._make_hash_binary({10: "1", 20: "0", 30: "1", 40: "0", 50: "1"})
        permutation = [10, 20, 30, 40, 50]
        data_bits = "1010"
        assert _check_marking(hash_binary, permutation, data_bits) == "marked"

    def test_unmarked_when_bits_mismatch_and_check_0(self):
        # extracted "0000" != "1010", check=0
        hash_binary = self._make_hash_binary({50: "0"})
        permutation = [10, 20, 30, 40, 50]
        data_bits = "1010"
        assert _check_marking(hash_binary, permutation, data_bits) == "unmarked"

    def test_discard_when_match_and_check_0(self):
        # extracted "0000" == "0000" but check=0
        hash_binary = self._make_hash_binary({50: "0"})
        permutation = [10, 20, 30, 40, 50]
        data_bits = "0000"
        assert _check_marking(hash_binary, permutation, data_bits) == "discard"

    def test_discard_when_mismatch_and_check_1(self):
        # extracted "0000" != "1010" but check=1
        hash_binary = self._make_hash_binary({50: "1"})
        permutation = [10, 20, 30, 40, 50]
        data_bits = "1010"
        assert _check_marking(hash_binary, permutation, data_bits) == "discard"


class TestRngSync:

    def test_identical_permutation_sequences(self):
        rng1 = random.Random(42)
        rng2 = random.Random(42)
        for _ in range(100):
            p1 = _generate_permutation(rng1, 5)
            p2 = _generate_permutation(rng2, 5)
            assert p1 == p2


class TestFullPipeline:

    def test_roundtrip_share_string(self):
        test_strings = [
            "1-abc123|2-def456",
            "3-ff00|4-abc",
        ]
        for original in test_strings:
            hex_str = _hex_encode(original)
            binary_str = _hex_to_binary(hex_str)
            recovered_hex = _binary_to_hex(binary_str)
            recovered = _hex_decode(recovered_hex)
            assert recovered == original, f"Failed for '{original}': got '{recovered}'"
