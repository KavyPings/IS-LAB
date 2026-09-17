"""
CONCEPT 06 : RABIN CRYPTOSYSTEM
(Lab 4 - HealthCare Inc. key management question)

Security is based on the difficulty of finding square roots mod n.

KEY GENERATION
  pick primes p, q  with  p = q = 3 (mod 4)   <- this makes decryption easy
  n = p*q
  public key  : n
  private key : (p, q)

ENCRYPT :  c = m^2 mod n
DECRYPT :  four possible roots come back - you need a way to spot the real one.
  mp = c^((p+1)/4) mod p
  mq = c^((q+1)/4) mod q
  combine with CRT ->  r1, r2 = n-r1, r3, r4 = n-r3

TRICK USED HERE: append a fixed marker (b"##") to the message before
encrypting. After decryption, the root that still ends with "##" is the
real message. This is the standard fix for Rabin's 4-way ambiguity.
"""

import random
import hashlib


def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x, y = egcd(b, a % b)
    return (g, y, x - (a // b) * y)


def is_prime(n, k=20):
    if n < 2:
        return False
    for sp in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % sp == 0:
            return n == sp
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_blum_prime(bits):
    """A 'Blum prime': prime AND congruent to 3 mod 4."""
    while True:
        cand = random.getrandbits(bits) | (1 << (bits - 1)) | 3
        if cand % 4 == 3 and is_prime(cand):
            return cand


def rabin_keygen(bits=1024):
    """bits = size of n. Each prime gets bits/2. Returns (n, (p, q))."""
    half = bits // 2
    p = gen_blum_prime(half)
    q = gen_blum_prime(half)
    while q == p:
        q = gen_blum_prime(half)
    return p * q, (p, q)


MARKER = b"##"        # redundancy so we can pick the correct root


def rabin_encrypt(message, n):
    data = message.encode() if isinstance(message, str) else message
    m = int.from_bytes(data + MARKER, "big")
    if m >= n:
        raise ValueError("message too long for this key size")
    return pow(m, 2, n)                     # c = m^2 mod n


def rabin_decrypt(c, p, q):
    """Return the one root that carries the marker (or all four if none does)."""
    n = p * q
    mp = pow(c, (p + 1) // 4, p)            # square root mod p
    mq = pow(c, (q + 1) // 4, q)            # square root mod q
    _, yp, yq = egcd(p, q)                  # yp*p + yq*q = 1
    r1 = (yp * p * mq + yq * q * mp) % n
    r2 = n - r1
    r3 = (yp * p * mq - yq * q * mp) % n
    r4 = n - r3
    for r in (r1, r2, r3, r4):
        b = r.to_bytes((r.bit_length() + 7) // 8 or 1, "big")
        if b.endswith(MARKER):
            return b[:-len(MARKER)]         # strip marker -> original message
    return [r1, r2, r3, r4]                 # marker not found: return all roots


def rabin_roots(c, p, q):
    """All four square roots, for questions that ask you to SHOW them."""
    n = p * q
    mp = pow(c, (p + 1) // 4, p)
    mq = pow(c, (q + 1) // 4, q)
    _, yp, yq = egcd(p, q)
    r1 = (yp * p * mq + yq * q * mp) % n
    r3 = (yp * p * mq - yq * q * mp) % n
    return [r1, n - r1, r3, n - r3]


# ---------------------------------------------------------------------------
# Rabin signature (rarely asked, but one line if it is)
# ---------------------------------------------------------------------------

def rabin_sign(message, p, q):
    """Sign by finding a square root of H(m) - only the key owner can."""
    n = p * q
    data = message.encode() if isinstance(message, str) else message
    for pad in range(1 << 16):              # nudge the hash until it is a QR
        h = int(hashlib.sha256(data + str(pad).encode()).hexdigest(), 16) % n
        if pow(h, (p - 1) // 2, p) == 1 and pow(h, (q - 1) // 2, q) == 1:
            mp = pow(h, (p + 1) // 4, p)
            mq = pow(h, (q + 1) // 4, q)
            _, yp, yq = egcd(p, q)
            s = (yp * p * mq + yq * q * mp) % n
            return s, pad
    raise RuntimeError("could not sign")


def rabin_verify(message, signature, n):
    s, pad = signature
    data = message.encode() if isinstance(message, str) else message
    h = int(hashlib.sha256(data + str(pad).encode()).hexdigest(), 16) % n
    return pow(s, 2, n) == h                # s^2 mod n must equal the hash


if __name__ == "__main__":
    n, (p, q) = rabin_keygen(1024)
    c = rabin_encrypt("Patient record 007", n)
    print("Rabin decrypt :", rabin_decrypt(c, p, q).decode())
    sig = rabin_sign("discharge summary", p, q)
    print("Rabin sig ok  :", rabin_verify("discharge summary", sig, n),
          "| tampered:", rabin_verify("discharge summaries", sig, n))
