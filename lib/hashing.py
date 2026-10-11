"""SHA-256 integrity tags for share strings."""

import hashlib


def append_hash(share_string):
    """Append the first 4 + last 4 hex chars of SHA-256 to the share."""
    h = hashlib.sha256(share_string.encode("utf-8")).hexdigest()
    hash_bits = h[:4] + h[-4:]
    return share_string + hash_bits


def verify_and_extract(hashed_share_string):
    """Check the trailing 8-char tag; return (True, share) or (False, None)."""
    if len(hashed_share_string) <= 8:
        return (False, None)

    original_share = hashed_share_string[:-8]
    extracted_hash = hashed_share_string[-8:]

    h = hashlib.sha256(original_share.encode("utf-8")).hexdigest()
    expected_hash = h[:4] + h[-4:]

    if extracted_hash == expected_hash:
        return (True, original_share)
    else:
        return (False, None)


if __name__ == "__main__":
    print("=" * 60)
    print("Hashing Module Verification")
    print("=" * 60)

    test_shares = ["1-390a1400234", "2-2dae573130d"]
    all_passed = True

    print("\n--- Test 1: Append hash to shares ---")
    for share in test_shares:
        hashed = append_hash(share)
        print(f"  Share:  {share}")
        print(f"  Hashed: {hashed}")
        print(f"  Added {len(hashed) - len(share)} chars")

        valid, extracted = verify_and_extract(hashed)
        status = "PASS" if (valid and extracted == share) else "FAIL"
        if status == "FAIL":
            all_passed = False
        print(f"  Verify: valid={valid}, extracted={extracted} -> {status}")
        print()

    print("--- Test 2: Tampered share detection ---")
    share = test_shares[0]
    hashed = append_hash(share)
    tampered = hashed[:5] + ("0" if hashed[5] != "0" else "1") + hashed[6:]
    valid, extracted = verify_and_extract(tampered)
    status = "PASS" if (not valid and extracted is None) else "FAIL"
    if status == "FAIL":
        all_passed = False
    print(f"  Original hashed: {hashed}")
    print(f"  Tampered:        {tampered}")
    print(f"  Verify: valid={valid}, extracted={extracted} -> {status}")
    print()

    print("--- Test 3: Too-short string ---")
    valid, extracted = verify_and_extract("short")
    status = "PASS" if (not valid and extracted is None) else "FAIL"
    if status == "FAIL":
        all_passed = False
    print(f"  Input: 'short'")
    print(f"  Verify: valid={valid}, extracted={extracted} -> {status}")
    print()

    print("=" * 60)
    print(f"Overall: {'ALL TESTS PASSED' if all_passed else 'SOME TESTS FAILED'}")
    print("=" * 60)
