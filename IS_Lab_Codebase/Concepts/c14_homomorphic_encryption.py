"""
=============================================================================
 CONCEPT 14 : PARTIAL HOMOMORPHIC ENCRYPTION   (Lab 7)
=============================================================================
Computing on data you cannot read.

  Paillier  multiply the ciphertexts -> ADD the plaintexts
  ElGamal   multiply the ciphertexts -> MULTIPLY the plaintexts
  RSA (raw) multiply the ciphertexts -> MULTIPLY the plaintexts, deterministic

PICK PAILLIER whenever the question says total, tally, sum, count, average or
"aggregate without revealing individual values".
PICK ELGAMAL or RAW RSA when the question says product or multiply.

Everything below is pure Python plus Crypto.Util.number, and every function is
pasteable on its own.
=============================================================================
"""

import random

from Crypto.Util.number import GCD, getPrime


# ---------------------------------------------------------------------------
# PAILLIER - additively homomorphic
# ---------------------------------------------------------------------------

def paillier_keygen(bits=512):
    """Returns (public, secret). public = {n, g, nn}; secret is lambda."""
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    while p == q:
        q = getPrime(bits // 2)
    n = p * q
    return {"n": n, "g": n + 1, "nn": n * n}, (p - 1) * (q - 1)


def paillier_encrypt(m, pub):
    """c = (1 + m*n) * r^n mod n^2 ; r fresh every time, so E(m) differs."""
    n, nn = pub["n"], pub["nn"]
    r = random.randrange(1, n)
    while GCD(r, n) != 1:
        r = random.randrange(1, n)
    return ((1 + (m % n) * n) * pow(r, n, nn)) % nn


def paillier_decrypt(c, pub, secret):
    """m = L(c^lambda mod n^2) * lambda^-1 mod n, with L(x) = (x-1)//n."""
    n, nn = pub["n"], pub["nn"]
    u = (pow(c, secret, nn) - 1) // n
    m = (u * pow(secret, -1, n)) % n
    return m - n if m > n // 2 else m          # map large values back to negative


def paillier_add(c1, c2, pub):
    """E(a) * E(b) -> E(a + b)."""
    return (c1 * c2) % pub["nn"]


def paillier_add_plain(c, k, pub):
    """E(a) * g^k -> E(a + k)."""
    return (c * pow(pub["g"], k % pub["n"], pub["nn"])) % pub["nn"]


def paillier_mul_plain(c, k, pub):
    """E(a)^k -> E(a * k)."""
    return pow(c, k, pub["nn"])


def paillier_sub(c1, c2, pub):
    """E(a) * E(b)^-1 -> E(a - b). Needed for any encrypted comparison."""
    return (c1 * pow(c2, -1, pub["nn"])) % pub["nn"]


def paillier_sum(ciphertexts, pub):
    """Total of a list of ciphertexts, starting from an encrypted zero."""
    total = paillier_encrypt(0, pub)
    for c in ciphertexts:
        total = paillier_add(total, c, pub)
    return total


# ---------------------------------------------------------------------------
# PACKED COUNTERS - how a vote tally gets a count PER option
# ---------------------------------------------------------------------------

def pack_counter(option, base=10 ** 6):
    """Encrypt pack_counter(option) instead of option, with base > voters."""
    return base ** int(option)


def unpack_counters(total, options, base=10 ** 6):
    """Read the per-option counts out of one decrypted number."""
    return {k: (total // (base ** k)) % base for k in options}


# ---------------------------------------------------------------------------
# ELGAMAL - multiplicatively homomorphic
# ---------------------------------------------------------------------------

def elgamal_he_keygen(bits=512):
    p = getPrime(bits)
    g = 2
    x = random.randrange(2, p - 2)
    return {"p": p, "g": g, "y": pow(g, x, p)}, x


def elgamal_he_encrypt(m, pub):
    p, g, y = pub["p"], pub["g"], pub["y"]
    r = random.randrange(2, p - 2)
    return (pow(g, r, p), (m * pow(y, r, p)) % p)


def elgamal_he_decrypt(c, pub, secret):
    p = pub["p"]
    return (c[1] * pow(c[0], -secret, p)) % p


def elgamal_he_multiply(c1, c2, pub):
    """(a1*a2, b1*b2) -> E(m1 * m2)."""
    p = pub["p"]
    return ((c1[0] * c2[0]) % p, (c1[1] * c2[1]) % p)


def elgamal_he_power(c, k, pub):
    """(a^k, b^k) -> E(m^k)."""
    p = pub["p"]
    return (pow(c[0], k, p), pow(c[1], k, p))


# ---------------------------------------------------------------------------
# TEXTBOOK RSA - multiplicatively homomorphic (no padding!)
# ---------------------------------------------------------------------------

def rsa_he_keygen(bits=512):
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    while p == q:
        q = getPrime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    while GCD(e, phi) != 1:
        e += 2
    return {"n": n, "e": e}, pow(e, -1, phi)


def rsa_he_encrypt(m, pub):
    return pow(m, pub["e"], pub["n"])


def rsa_he_decrypt(c, pub, secret):
    return pow(c, secret, pub["n"])


def rsa_he_multiply(c1, c2, pub):
    """E(a) * E(b) -> E(a * b)."""
    return (c1 * c2) % pub["n"]


# ---------------------------------------------------------------------------
# ENCRYPTED COMPARISON - the honest version
#   ElGamal cannot compare. Paillier can subtract, and the key holder can be
#   asked to publish only the SIGN of the difference.
# ---------------------------------------------------------------------------

def paillier_compare(c, threshold, pub, secret):
    """Returns +1 if m > threshold, 0 if equal, -1 if less. One bit leaks."""
    difference = paillier_decrypt(paillier_add_plain(c, -threshold, pub), pub, secret)
    return (difference > 0) - (difference < 0)


if __name__ == "__main__":
    print("--- Paillier: addition on encrypted data ---")
    pub, secret = paillier_keygen(512)
    a, b = paillier_encrypt(15, pub), paillier_encrypt(25, pub)
    print("E(15) + E(25) ->", paillier_decrypt(paillier_add(a, b, pub), pub, secret))
    print("E(15) + 100   ->", paillier_decrypt(paillier_add_plain(a, 100, pub), pub, secret))
    print("E(15) * 3     ->", paillier_decrypt(paillier_mul_plain(a, 3, pub), pub, secret))
    print("E(25) - E(15) ->", paillier_decrypt(paillier_sub(b, a, pub), pub, secret))
    print("sum of 1..5   ->", paillier_decrypt(
        paillier_sum([paillier_encrypt(i, pub) for i in range(1, 6)], pub), pub, secret))

    print("\n--- packed counters: three votes for option 2, one for option 1 ---")
    votes = [2, 2, 2, 1]
    total = paillier_sum([paillier_encrypt(pack_counter(v, 1000), pub) for v in votes], pub)
    print(unpack_counters(paillier_decrypt(total, pub, secret), [1, 2, 3], 1000))

    print("\n--- ElGamal: multiplication on encrypted data ---")
    epub, esecret = elgamal_he_keygen(512)
    ea, eb = elgamal_he_encrypt(12, epub), elgamal_he_encrypt(7, epub)
    print("E(12) * E(7) ->", elgamal_he_decrypt(
        elgamal_he_multiply(ea, eb, epub), epub, esecret))
    print("E(12)^3      ->", elgamal_he_decrypt(
        elgamal_he_power(ea, 3, epub), epub, esecret))

    print("\n--- textbook RSA: multiplication on encrypted data ---")
    rpub, rsecret = rsa_he_keygen(512)
    ra, rb = rsa_he_encrypt(7, rpub), rsa_he_encrypt(3, rpub)
    print("E(7) * E(3)  ->", rsa_he_decrypt(rsa_he_multiply(ra, rb, rpub), rpub, rsecret))

    print("\n--- encrypted comparison against 130 ---")
    for reading in [118, 130, 165]:
        sign = paillier_compare(paillier_encrypt(reading, pub), 130, pub, secret)
        print("  reading", reading, "->",
              "HIGH" if sign > 0 else ("equal" if sign == 0 else "normal"))
