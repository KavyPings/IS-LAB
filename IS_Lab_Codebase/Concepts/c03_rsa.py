"""
CONCEPT 03 : RSA  (asymmetric encryption + digital signature)
(Lab 3 / Lab 4 / Lab 6)

Two ways to do RSA - use whichever the question needs:

  A) LIBRARY RSA (pycryptodome)  -> real 2048-bit keys, OAEP/PSS padding.
     Use for: "encrypt a message/file", "sign a document", secure systems.

  B) TEXTBOOK RSA (plain python) -> you are GIVEN small n, e, d (e.g. n=323).
     Use for: "encrypt with public key (n=323, e=5)" style questions.

RSA MATHS RECAP
  n = p*q            phi = (p-1)(q-1)
  gcd(e, phi) = 1    d = e^-1 mod phi
  encrypt: c = m^e mod n      decrypt: m = c^d mod n
  sign   : s = h^d mod n      verify : h = s^e mod n
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pkcs1_15, pss
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import random


# ===========================================================================
# A)  LIBRARY RSA
# ===========================================================================

def rsa_generate(bits=2048):
    """Generate an RSA key pair. Returns the key object.
    key.publickey() -> public part ; key itself holds the private part."""
    return RSA.generate(bits)


def rsa_encrypt(message, public_key):
    """Encrypt with OAEP padding. NOTE: max message size is about
    (key_bytes - 42). For 2048-bit keys that is ~214 bytes."""
    data = message.encode() if isinstance(message, str) else message
    return PKCS1_OAEP.new(public_key).encrypt(data)


def rsa_decrypt(ciphertext, private_key):
    return PKCS1_OAEP.new(private_key).decrypt(ciphertext)


def rsa_sign(message, private_key):
    """Digital signature = RSA over the SHA-256 hash of the message."""
    data = message.encode() if isinstance(message, str) else message
    h = SHA256.new(data)
    return pkcs1_15.new(private_key).sign(h)


def rsa_verify(message, signature, public_key):
    """Returns True/False instead of raising - easier to use in a menu."""
    data = message.encode() if isinstance(message, str) else message
    h = SHA256.new(data)
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


def rsa_sign_pss(message, private_key):
    """PSS is the modern (probabilistic) signature padding. Same idea."""
    data = message.encode() if isinstance(message, str) else message
    return pss.new(private_key).sign(SHA256.new(data))


def rsa_verify_pss(message, signature, public_key):
    data = message.encode() if isinstance(message, str) else message
    try:
        pss.new(public_key).verify(SHA256.new(data), signature)
        return True
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------------------------
# HYBRID ENCRYPTION - the correct way to RSA-encrypt a big file
#   RSA can only encrypt ~200 bytes, so:
#   1) make a random AES key, 2) AES-encrypt the data,
#   3) RSA-encrypt the AES key. Send both.
# ---------------------------------------------------------------------------

def rsa_encrypt_large(data, public_key):
    """Returns (encrypted_aes_key, nonce, tag, ciphertext)."""
    data = data.encode() if isinstance(data, str) else data
    session_key = get_random_bytes(16)                   # random AES-128 key
    cipher = AES.new(session_key, AES.MODE_EAX)          # EAX = encrypt + auth
    ct, tag = cipher.encrypt_and_digest(data)
    enc_key = PKCS1_OAEP.new(public_key).encrypt(session_key)
    return enc_key, cipher.nonce, tag, ct


def rsa_decrypt_large(enc_key, nonce, tag, ct, private_key):
    session_key = PKCS1_OAEP.new(private_key).decrypt(enc_key)
    cipher = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)


def save_keys(key, priv_file="private.pem", pub_file="public.pem"):
    """Write keys to PEM files (questions often say 'store keys securely')."""
    with open(priv_file, "wb") as f:
        f.write(key.export_key())
    with open(pub_file, "wb") as f:
        f.write(key.publickey().export_key())


def load_key(path):
    with open(path, "rb") as f:
        return RSA.import_key(f.read())


# ===========================================================================
# B)  TEXTBOOK RSA  (small numbers given in the question)
# ===========================================================================

def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x, y = egcd(b, a % b)
    return (g, y, x - (a // b) * y)


def modinv(a, m):
    """Modular inverse using extended Euclid - works for huge numbers."""
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError("no modular inverse")
    return x % m


def rsa_keygen_manual(p, q, e=65537):
    """Build (n,e) and (n,d) from two primes - shows the actual RSA steps."""
    n = p * q
    phi = (p - 1) * (q - 1)
    if egcd(e, phi)[0] != 1:
        raise ValueError("e is not coprime with phi(n)")
    d = modinv(e, phi)
    return (n, e), (n, d)


def rsa_encrypt_manual(message, n, e):
    """Encrypt each CHARACTER separately: c = ord(ch)^e mod n.
    Use this when n is small (like 323) - a whole message will not fit."""
    return [pow(ord(ch), e, n) for ch in message]


def rsa_decrypt_manual(cipher_list, n, d):
    return "".join(chr(pow(c, d, n)) for c in cipher_list)


def rsa_encrypt_int(m, n, e):
    """Encrypt one integer (m must be < n)."""
    return pow(m, e, n)


def rsa_decrypt_int(c, n, d):
    return pow(c, d, n)


def bytes_to_int(b):
    return int.from_bytes(b, "big")


def int_to_bytes(i):
    return i.to_bytes((i.bit_length() + 7) // 8 or 1, "big")


# ---------------------------------------------------------------------------
# RSA ATTACK: factor n when p and q are too close together (Fermat's method)
# Lab 4 additional Q2 asks exactly this.
# ---------------------------------------------------------------------------

def fermat_factor(n, max_steps=1_000_000):
    """If p and q are close, n = a^2 - b^2 = (a-b)(a+b) is found fast."""
    import math
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(max_steps):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:                      # perfect square -> factors found
            return a - b, a + b
        a += 1
    return None


def recover_private_key(n, e, p, q):
    """Once p,q are known the private exponent falls out immediately."""
    phi = (p - 1) * (q - 1)
    return modinv(e, phi)


def is_prime(num, k=20):
    """Miller-Rabin primality test - needed to generate your own primes."""
    if num < 2:
        return False
    for sp in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if num % sp == 0:
            return num == sp
    d, r = num - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(k):
        a = random.randrange(2, num - 1)
        x = pow(a, d, num)
        if x in (1, num - 1):
            continue
        for _ in range(r - 1):
            x = x * x % num
            if x == num - 1:
                break
        else:
            return False
    return True


def gen_prime(bits):
    """Random prime of the requested bit length."""
    while True:
        cand = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_prime(cand):
            return cand


if __name__ == "__main__":
    key = rsa_generate(2048)
    ct = rsa_encrypt("Asymmetric Encryption", key.publickey())
    print("RSA lib  :", ct.hex()[:48], "...")
    print("decrypted:", rsa_decrypt(ct, key).decode())
    sig = rsa_sign("hello", key)
    print("signature verifies:", rsa_verify("hello", sig, key.publickey()))

    # textbook RSA with the manual's numbers
    n, e, d = 323, 5, 173
    cl = rsa_encrypt_manual("Hi", n, e)
    print("textbook :", cl, "->", rsa_decrypt_manual(cl, n, d))

    # attack demo
    p = gen_prime(64); q = gen_prime(64)
    print("fermat on close primes:", fermat_factor(1000003 * 1000033))
