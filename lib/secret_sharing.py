"""Shamir's Secret Sharing over GF(2^127 - 1): split and reconstruct."""

import secrets


_DEFAULT_PRIME = (2 ** 127) - 1


def split_secret(secret_string, k, n, prime=None):
    """Split a secret string into n shares, k of which can reconstruct it."""
    if not secret_string:
        raise ValueError("Secret message cannot be empty")
    if k < 2:
        raise ValueError(f"Threshold k must be at least 2, got {k}")
    if k > n:
        raise ValueError(f"Threshold k ({k}) cannot exceed total shares n ({n})")

    if prime is None:
        prime = _DEFAULT_PRIME

    secret_int = int.from_bytes(secret_string.encode('utf-8'), 'big')

    if secret_int >= prime:
        raise ValueError(
            f"Message too large for prime (message integer has "
            f"{secret_int.bit_length()} bits, prime has {prime.bit_length()} bits)"
        )

    # a0 = secret, remaining coefficients random
    coefficients = [secret_int] + [
        secrets.randbelow(prime - 1) + 1 for _ in range(k - 1)
    ]

    # Evaluate at x = 1..n via Horner's method
    shares = []
    for x in range(1, n + 1):
        y = 0
        for coeff in reversed(coefficients):
            y = (y * x + coeff) % prime
        shares.append(f"{x}-{y:x}")

    return shares


def reconstruct_secret(shares, prime=None):
    """Recover the secret from k+ shares via Lagrange interpolation at x=0."""
    if len(shares) < 2:
        raise ValueError(f"Need at least 2 shares, got {len(shares)}")

    if prime is None:
        prime = _DEFAULT_PRIME

    points = []
    for share in shares:
        parts = share.split("-", 1)
        x = int(parts[0])
        y = int(parts[1], 16)
        points.append((x, y))

    secret = 0
    for i, (xi, yi) in enumerate(points):
        numerator = 1
        denominator = 1
        for j, (xj, _) in enumerate(points):
            if i == j:
                continue
            numerator = (numerator * (-xj)) % prime
            denominator = (denominator * (xi - xj)) % prime
        # modular inverse via Fermat's little theorem
        lagrange_coeff = (numerator * pow(denominator, prime - 2, prime)) % prime
        secret = (secret + yi * lagrange_coeff) % prime

    byte_length = max(1, (secret.bit_length() + 7) // 8)
    return secret.to_bytes(byte_length, 'big').decode('utf-8')


if __name__ == "__main__":
    print("=" * 60)
    print("Shamir's Secret Sharing -- Verification")
    print("=" * 60)

    all_passed = True

    msg = "Attack at dawn"
    print(f"\n[TEST 1] Message: '{msg}'")
    shares = split_secret(msg, 4, 7)
    for i, s in enumerate(shares, 1):
        print(f"  Share {i}: {s}")

    r1 = reconstruct_secret(shares[:4])
    status = "PASS" if r1 == msg else "FAIL"
    if r1 != msg:
        all_passed = False
    print(f"  Reconstruct (first 4): '{r1}' -- {status}")

    selected = [shares[0], shares[2], shares[4], shares[6]]
    r2 = reconstruct_secret(selected)
    status = "PASS" if r2 == msg else "FAIL"
    if r2 != msg:
        all_passed = False
    print(f"  Reconstruct (1,3,5,7): '{r2}' -- {status}")

    r3 = reconstruct_secret(shares)
    status = "PASS" if r3 == msg else "FAIL"
    if r3 != msg:
        all_passed = False
    print(f"  Reconstruct (all 7):   '{r3}' -- {status}")

    msg2 = "Hi"
    print(f"\n[TEST 2] Message: '{msg2}'")
    shares2 = split_secret(msg2, 4, 7)
    r4 = reconstruct_secret(shares2[:4])
    status = "PASS" if r4 == msg2 else "FAIL"
    if r4 != msg2:
        all_passed = False
    print(f"  Reconstruct (first 4): '{r4}' -- {status}")

    msg3 = "The quick brown fox jumps over the lazy dog!"
    print(f"\n[TEST 3] Message: '{msg3}'")
    shares3 = split_secret(msg3, 4, 7)
    r5 = reconstruct_secret(shares3[:4])
    status = "PASS" if r5 == msg3 else "FAIL"
    if r5 != msg3:
        all_passed = False
    print(f"  Reconstruct (first 4): '{r5}' -- {status}")

    msg4 = "Bonjour le monde"
    print(f"\n[TEST 4] Message: '{msg4}'")
    shares4 = split_secret(msg4, 4, 7)
    r6 = reconstruct_secret(shares4[:4])
    status = "PASS" if r6 == msg4 else "FAIL"
    if r6 != msg4:
        all_passed = False
    print(f"  Reconstruct (first 4): '{r6}' -- {status}")

    print("\n" + "=" * 60)
    print(f"Overall: {'ALL TESTS PASSED' if all_passed else 'SOME TESTS FAILED'}")
    print("=" * 60)
