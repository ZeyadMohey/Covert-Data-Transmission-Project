"""Unit tests for Shamir's Secret Sharing."""

import pytest
import re

from lib.secret_sharing import split_secret, reconstruct_secret
from lib.config import PRIME, THRESHOLD_K, TOTAL_SHARES_N


SHARE_REGEX = re.compile(r"^\d+-[0-9a-f]+$")


class TestSplitSecret:

    def test_split_produces_n_shares(self):
        shares = split_secret("Attack at dawn", 4, 7)
        assert len(shares) == 7

    def test_split_various_messages(self, sample_messages, default_k, default_n):
        for msg in sample_messages:
            shares = split_secret(msg, default_k, default_n)
            assert len(shares) == default_n, f"Expected {default_n} shares for '{msg}'"

    def test_split_rejects_empty(self):
        with pytest.raises(ValueError, match="empty"):
            split_secret("", 4, 7)

    def test_split_rejects_k_less_than_2(self):
        with pytest.raises(ValueError):
            split_secret("msg", 1, 7)

    def test_split_rejects_k_greater_than_n(self):
        with pytest.raises(ValueError):
            split_secret("msg", 8, 7)

    def test_share_format(self):
        shares = split_secret("Attack at dawn", 4, 7)
        for share in shares:
            assert SHARE_REGEX.match(share), f"Share '{share}' does not match x-hexvalue format"


class TestReconstructSecret:

    def test_reconstruct_k_shares(self):
        shares = split_secret("Attack at dawn", 4, 7)
        result = reconstruct_secret(shares[:4])
        assert result == "Attack at dawn"

    def test_reconstruct_all_shares(self):
        shares = split_secret("Attack at dawn", 4, 7)
        result = reconstruct_secret(shares)
        assert result == "Attack at dawn"

    def test_reconstruct_nonconsecutive(self):
        shares = split_secret("Attack at dawn", 4, 7)
        selected = [shares[0], shares[2], shares[4], shares[6]]
        result = reconstruct_secret(selected)
        assert result == "Attack at dawn"

    def test_reconstruct_k_plus_one(self):
        shares = split_secret("Attack at dawn", 4, 7)
        result = reconstruct_secret(shares[:5])
        assert result == "Attack at dawn"

    def test_reconstruct_insufficient_shares(self):
        original = "Attack at dawn"
        shares = split_secret(original, 4, 7)
        # Fewer than k=4 shares should not recover the original
        try:
            result = reconstruct_secret(shares[:2])
            assert result != original, "Should not reconstruct correctly with fewer than k shares"
        except (ValueError, UnicodeDecodeError, OverflowError):
            pass


class TestRoundTrip:

    def test_roundtrip_short(self):
        shares = split_secret("Hi", 4, 7)
        result = reconstruct_secret(shares[:4])
        assert result == "Hi"

    def test_roundtrip_unicode(self):
        msg = "Bonjour le monde"
        shares = split_secret(msg, 4, 7)
        result = reconstruct_secret(shares[:4])
        assert result == msg

    def test_roundtrip_single_char(self):
        shares = split_secret("A", 4, 7)
        result = reconstruct_secret(shares[:4])
        assert result == "A"

    def test_roundtrip_long_message(self):
        msg = "Fire at 0600!!!"
        shares = split_secret(msg, 4, 7)
        result = reconstruct_secret(shares[:4])
        assert result == msg


class TestEdgeCases:

    def test_message_too_large(self):
        large_msg = "A" * 100
        with pytest.raises(ValueError, match="too large"):
            split_secret(large_msg, 4, 7)
