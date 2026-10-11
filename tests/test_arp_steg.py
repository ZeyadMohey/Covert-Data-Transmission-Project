"""Unit tests for ARP steganography helpers."""

import random

import pytest

from lib.arp_steg import (
    _decode_payload,
    _encode_payload,
    _filter_usable_ips,
    _hex_decode,
    _hex_encode,
    _hex_to_chunks,
    _int_to_mac,
    _mac_to_int,
    _xor_encrypt,
)
from lib.config import generate_48bit_key


class TestHexEncodeDecode:

    def test_hex_encode_decode(self):
        original = "1-abc|2-def"
        encoded = _hex_encode(original)
        assert encoded == "312d6162637c322d646566"
        decoded = _hex_decode(encoded)
        assert decoded == original

    def test_hex_encode_decode_empty(self):
        assert _hex_decode(_hex_encode("")) == ""

    def test_hex_encode_decode_special_chars(self):
        original = "3-ff00|4-abc123"
        assert _hex_decode(_hex_encode(original)) == original


class TestHexToChunks:

    def test_hex_to_chunks_exact_multiple(self):
        hex_str = "a" * 22
        chunks = _hex_to_chunks(hex_str)
        assert len(chunks) == 2
        assert chunks[0] == ("a" * 11, "0")
        assert chunks[1] == ("a" * 11, "f")

    def test_hex_to_chunks_with_padding(self):
        hex_str = "a" * 15
        chunks = _hex_to_chunks(hex_str)
        assert len(chunks) == 2
        assert chunks[0] == ("a" * 11, "0")
        assert chunks[1] == ("a" * 4 + "0" * 7, "7")

    def test_hex_to_chunks_single_full(self):
        hex_str = "b" * 11
        chunks = _hex_to_chunks(hex_str)
        assert len(chunks) == 1
        assert chunks[0] == ("b" * 11, "f")

    def test_hex_to_chunks_single_partial(self):
        hex_str = "c" * 5
        chunks = _hex_to_chunks(hex_str)
        assert len(chunks) == 1
        assert chunks[0] == ("c" * 5 + "0" * 6, "6")

    def test_hex_to_chunks_single_char(self):
        hex_str = "d"
        chunks = _hex_to_chunks(hex_str)
        assert len(chunks) == 1
        assert chunks[0] == ("d" + "0" * 10, "a")


class TestControlQuadValues:

    def test_control_quad_last_full(self):
        chunks = _hex_to_chunks("a" * 11)
        assert chunks[-1][1] == "f"

    def test_control_quad_padding_3(self):
        chunks = _hex_to_chunks("a" * 19)
        assert chunks[-1][1] == "3"

    def test_control_quad_padding_10(self):
        chunks = _hex_to_chunks("a" * 12)
        assert chunks[-1][1] == "a"


class TestXorEncrypt:

    def test_xor_roundtrip(self):
        data = 0xAABBCCDDEEFF
        key = 0x112233445566
        encrypted = _xor_encrypt(data, key)
        decrypted = _xor_encrypt(encrypted, key)
        assert decrypted == data

    def test_xor_zero_data(self):
        key = 0xDEADBEEFCAFE
        encrypted = _xor_encrypt(0, key)
        assert encrypted == key
        assert _xor_encrypt(encrypted, key) == 0

    def test_xor_max_data(self):
        data = (1 << 48) - 1
        key = 0x123456789ABC
        encrypted = _xor_encrypt(data, key)
        decrypted = _xor_encrypt(encrypted, key)
        assert decrypted == data

    def test_xor_random_values(self):
        rng = random.Random(99)
        for _ in range(10):
            data = rng.getrandbits(48)
            key = rng.getrandbits(48)
            assert _xor_encrypt(_xor_encrypt(data, key), key) == data


class TestIntToMac:

    def test_int_to_mac_known_value(self):
        assert _int_to_mac(0xAABBCCDDEEFF) == "aa:bb:cc:dd:ee:ff"

    def test_int_to_mac_zero(self):
        assert _int_to_mac(0) == "00:00:00:00:00:00"

    def test_int_to_mac_max(self):
        assert _int_to_mac((1 << 48) - 1) == "ff:ff:ff:ff:ff:ff"


class TestMacToInt:

    def test_mac_to_int_known_value(self):
        assert _mac_to_int("aa:bb:cc:dd:ee:ff") == 0xAABBCCDDEEFF

    def test_mac_to_int_roundtrip(self):
        value = 0x1234567890AB
        mac = _int_to_mac(value)
        assert _mac_to_int(mac) == value

    def test_mac_to_int_zero(self):
        assert _mac_to_int("00:00:00:00:00:00") == 0


class TestEncodeDecodePayload:

    def test_encode_decode_payload_continue(self):
        data_hex = "1234567890a"
        control = "0"
        encoded = _encode_payload(data_hex, control)
        decoded_data, decoded_control = _decode_payload(encoded)
        assert decoded_data == data_hex
        assert decoded_control == control

    def test_encode_decode_payload_last_full(self):
        data_hex = "abcdef01234"
        control = "f"
        encoded = _encode_payload(data_hex, control)
        decoded_data, decoded_control = _decode_payload(encoded)
        assert decoded_data == data_hex
        assert decoded_control == control

    def test_encode_decode_payload_padding(self):
        data_hex = "1234560000"
        data_hex_padded = data_hex + "0"
        control = "5"
        encoded = _encode_payload(data_hex_padded, control)
        decoded_data, decoded_control = _decode_payload(encoded)
        assert decoded_data == data_hex_padded
        assert decoded_control == control


class TestFilterUsableIps:

    def test_filter_usable_ips(self):
        random_ips = [
            "192.168.100.5",
            "192.168.100.3",
            "192.168.100.5",
            "192.168.100.10",
        ]
        allocated = {"192.168.100.3", "192.168.100.6"}
        result = _filter_usable_ips(random_ips, allocated)
        assert result == ["192.168.100.5", "192.168.100.10"]

    def test_filter_usable_ips_all_allocated(self):
        random_ips = ["192.168.100.3", "192.168.100.6"]
        allocated = {"192.168.100.3", "192.168.100.6"}
        result = _filter_usable_ips(random_ips, allocated)
        assert result == []

    def test_filter_usable_ips_no_allocated(self):
        random_ips = ["192.168.100.5", "192.168.100.10", "192.168.100.5"]
        allocated = set()
        result = _filter_usable_ips(random_ips, allocated)
        assert result == ["192.168.100.5", "192.168.100.10"]


class TestFullRoundtrip:

    def test_full_encode_decode_roundtrip(self):
        test_strings = [
            "1-abc123|2-def456",
            "3-ff00|4-abc123|5-deadbeef",
            "1-a",
        ]

        for original in test_strings:
            # sender side
            sender_rng = random.Random(42)
            hex_data = _hex_encode(original)
            chunks = _hex_to_chunks(hex_data)

            encrypted_payloads = []
            for data_hex, control in chunks:
                payload_int = _encode_payload(data_hex, control)
                key = generate_48bit_key(sender_rng)
                encrypted = _xor_encrypt(payload_int, key)
                encrypted_payloads.append(encrypted)

            # receiver side
            receiver_rng = random.Random(42)
            received_hex = ""

            for encrypted_val in encrypted_payloads:
                key = generate_48bit_key(receiver_rng)
                decrypted = _xor_encrypt(encrypted_val, key)
                data_hex, control = _decode_payload(decrypted)

                if control == "0":
                    received_hex += data_hex
                elif control == "f":
                    received_hex += data_hex
                else:
                    padding_count = int(control, 16)
                    received_hex += data_hex[:-padding_count] if padding_count > 0 else data_hex

            recovered = _hex_decode(received_hex)
            assert recovered == original, f"Failed for '{original}': got '{recovered}'"
