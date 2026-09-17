"""
CONCEPT 04 : ELGAMAL  (encryption + digital signature)
(Lab 3, Lab 4, Lab 6)

Pure python - no library needed, because pycryptodome dropped ElGamal.

KEYS
  public parameters : large prime p, generator g
  private key       : x   (random, 1 <= x <= p-2)
  public key        : y = g^x mod p       -> public key is (p, g, y)

ENCRYPT (message m, 0 <= m < p)
  pick random k
  c1 = g^k mod p
  c2 = m * y^k mod p          ciphertext = (c1, c2)

DECRYPT
  s = c1^x mod p
  m = c2 * s^-1 mod p

SIGN (message hash h)
  pick random k with gcd(k, p-1) = 1
  r = g^k mod p
  s = (h - x*r) * k^-1 mod (p-1)          signature = (r, s)

VERIFY
  check   g^h  ==  y^r * r^s   (mod p)
"""

import random
import hashlib


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x, y = egcd(b, a % b)
    return (g, y, x - (a // b) * y)


def modinv(a, m):
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError("no inverse")
    return x % m


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


def gen_safe_prime(bits):
    """p = 2q+1 with q prime. Then g=2 is (almost always) a good generator."""
    while True:
        q = random.getrandbits(bits - 1) | (1 << (bits - 2)) | 1
        if is_prime(q):
            p = 2 * q + 1
            if is_prime(p):
                return p, q


# ---------------------------------------------------------------------------
# KEY GENERATION
# ---------------------------------------------------------------------------

def elgamal_keygen(bits=256):
    """Returns (public_key, private_key) = ((p, g, y), x).
    Keep bits small (256) in an exam - 2048-bit safe primes take minutes."""
    p, q = gen_safe_prime(bits)
    g = 2
    x = random.randrange(2, p - 2)          # private key
    y = pow(g, x, p)                        # public key component
    return (p, g, y), x


# ---------------------------------------------------------------------------
# ENCRYPTION / DECRYPTION
# ---------------------------------------------------------------------------

def elgamal_encrypt_int(m, pub):
    """Encrypt one integer m (must satisfy m < p)."""
    p, g, y = pub
    k = random.randrange(2, p - 2)          # fresh random k for EVERY message
    c1 = pow(g, k, p)
    c2 = (m * pow(y, k, p)) % p
    return (c1, c2)


def elgamal_decrypt_int(ct, priv, p):
    c1, c2 = ct
    s = pow(c1, priv, p)                    # shared secret = c1^x
    return (c2 * modinv(s, p)) % p


def elgamal_encrypt(message, pub):
    """Encrypt a STRING. If the whole message fits in one integer (< p) we send
    one block; otherwise we fall back to one block per character."""
    p, g, y = pub
    data = message.encode() if isinstance(message, str) else message
    m = int.from_bytes(data, "big")
    if m < p:
        return [elgamal_encrypt_int(m, pub)], "whole"
    return [elgamal_encrypt_int(b, pub) for b in data], "bytes"


def elgamal_decrypt(cipher, priv, pub, mode):
    p = pub[0]
    if mode == "whole":
        m = elgamal_decrypt_int(cipher[0], priv, p)
        return m.to_bytes((m.bit_length() + 7) // 8 or 1, "big").decode()
    return bytes(elgamal_decrypt_int(c, priv, p) for c in cipher).decode()


def elgamal_encrypt_chars(message, pub):
    """Per-character version - use when p is TINY (e.g. p = 7919 in the manual)."""
    return [elgamal_encrypt_int(ord(ch), pub) for ch in message]


def elgamal_decrypt_chars(cipher, priv, p):
    return "".join(chr(elgamal_decrypt_int(c, priv, p)) for c in cipher)


# ---------------------------------------------------------------------------
# DIGITAL SIGNATURE
# ---------------------------------------------------------------------------

def elgamal_sign(message, priv, pub):
    """Signature = (r, s). Hash is reduced mod (p-1)."""
    p, g, y = pub
    data = message.encode() if isinstance(message, str) else message
    h = int(hashlib.sha256(data).hexdigest(), 16) % (p - 1)
    while True:
        k = random.randrange(2, p - 2)
        if egcd(k, p - 1)[0] == 1:          # k must be invertible mod p-1
            break
    r = pow(g, k, p)
    s = ((h - priv * r) * modinv(k, p - 1)) % (p - 1)
    return (r, s)


def elgamal_verify(message, signature, pub):
    p, g, y = pub
    r, s = signature
    if not (0 < r < p):
        return False
    data = message.encode() if isinstance(message, str) else message
    h = int(hashlib.sha256(data).hexdigest(), 16) % (p - 1)
    left = pow(g, h, p)                      # g^h
    right = (pow(y, r, p) * pow(r, s, p)) % p  # y^r * r^s
    return left == right


# ---------------------------------------------------------------------------
# SCHNORR SIGNATURE (asked in Lab 6 Q1) - shorter/faster than ElGamal
#   r = g^k mod p ; e = H(r || m) mod q ; s = (k + x*e) mod q
#   verify: g^s * y^-e mod p == r
# ---------------------------------------------------------------------------

def schnorr_keygen(bits=256):
    p, q = gen_safe_prime(bits)
    g = pow(2, (p - 1) // q, p)              # g has order q
    x = random.randrange(1, q)
    y = pow(g, x, p)
    return (p, q, g, y), x


def schnorr_sign(message, priv, pub):
    p, q, g, y = pub
    data = message.encode() if isinstance(message, str) else message
    k = random.randrange(1, q)
    r = pow(g, k, p)
    e = int(hashlib.sha256(str(r).encode() + data).hexdigest(), 16) % q
    s = (k + priv * e) % q
    return (e, s)


def schnorr_verify(message, signature, pub):
    p, q, g, y = pub
    e, s = signature
    data = message.encode() if isinstance(message, str) else message
    rv = (pow(g, s, p) * pow(y, q - e % q, p)) % p   # g^s * y^(-e)
    ev = int(hashlib.sha256(str(rv).encode() + data).hexdigest(), 16) % q
    return ev == e


if __name__ == "__main__":
    pub, priv = elgamal_keygen(256)
    ct, mode = elgamal_encrypt("Confidential Data", pub)
    print("ElGamal decrypt:", elgamal_decrypt(ct, priv, pub, mode))
    sig = elgamal_sign("contract", priv, pub)
    print("ElGamal sig ok :", elgamal_verify("contract", sig, pub))
    print("tampered       :", elgamal_verify("contracT", sig, pub))

    # tiny p, per-character mode (manual style). NOTE: y MUST equal g^x mod p,
    # otherwise decryption returns garbage - see Lab3/additional_questions/q1.py
    p_s, g_s, x_s = 7919, 2, 2999
    small_pub = (p_s, g_s, pow(g_s, x_s, p_s))
    cl = elgamal_encrypt_chars("Asymmetric Algorithms", small_pub)
    print("tiny p decrypt :", elgamal_decrypt_chars(cl, x_s, p_s))

    spub, spriv = schnorr_keygen(256)
    ssig = schnorr_sign("doc", spriv, spub)
    print("Schnorr ok     :", schnorr_verify("doc", ssig, spub),
          "| tampered:", schnorr_verify("doc2", ssig, spub))
