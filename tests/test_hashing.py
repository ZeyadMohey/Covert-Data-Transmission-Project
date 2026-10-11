"""Unit tests for lib/hashing.py (append + verify integrity tags)."""

import hashlib

import pytest

from lib.hashing import append_hash, verify_and_extract


def test_append_hash_length():
    share = "1-390a1400234"
    result = append_hash(share)
    assert len(result) == len(share) + 8


def test_append_hash_deterministic():
    share = "1-390a1400234"
    assert append_hash(share) == append_hash(share)


def test_append_hash_correct_bits():
    share = "1-390a1400234"
    h = hashlib.sha256(share.encode("utf-8")).hexdigest()
    expected_suffix = h[:4] + h[-4:]
    result = append_hash(share)
    assert result == share + expected_suffix
    assert result[-8:] == expected_suffix


def test_verify_valid_share():
    share = "1-390a1400234"
    hashed = append_hash(share)
    valid, extracted = verify_and_extract(hashed)
    assert valid is True
    assert extracted == share


def test_verify_tampered_share():
    share = "1-390a1400234"
    hashed = append_hash(share)
    # Flip a char in the share body, not the trailing 8 hash chars
    tampered = hashed[:5] + ("0" if hashed[5] != "0" else "1") + hashed[6:]
    valid, extracted = verify_and_extract(tampered)
    assert valid is False
    assert extracted is None


def test_verify_tampered_hash_bits():
    share = "1-390a1400234"
    hashed = append_hash(share)
    last_char = hashed[-1]
    new_char = "0" if last_char != "0" else "1"
    tampered = hashed[:-1] + new_char
    valid, extracted = verify_and_extract(tampered)
    assert valid is False
    assert extracted is None


def test_verify_too_short():
    assert verify_and_extract("abcdefgh") == (False, None)
    assert verify_and_extract("short") == (False, None)


def test_verify_empty_string():
    assert verify_and_extract("") == (False, None)


def test_multiple_shares():
    shares = ["1-390a1400234", "2-2dae573130d", "7-abcdef01234"]
    for share in shares:
        hashed = append_hash(share)
        assert len(hashed) == len(share) + 8
        valid, extracted = verify_and_extract(hashed)
        assert valid is True
        assert extracted == share


def test_roundtrip_with_real_shares():
    ss = pytest.importorskip("lib.secret_sharing")
    shares = ss.split_secret("Attack at dawn", k=4, n=7)
    for share in shares:
        hashed = append_hash(share)
        valid, extracted = verify_and_extract(hashed)
        assert valid is True
        assert extracted == share
