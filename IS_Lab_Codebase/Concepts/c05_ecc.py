"""
CONCEPT 05 : ELLIPTIC CURVE CRYPTOGRAPHY (ECC)
(Lab 3, Lab 4, Lab 6)

IMPORTANT IDEA:
  ECC does NOT encrypt messages directly. It gives you
    - ECDH : two parties agree on a shared secret
    - ECDSA: digital signatures
  To "encrypt a message with ECC" you use ECIES:
      ephemeral ECDH  ->  derive an AES key  ->  AES-encrypt the message.
  That is exactly what ecc_encrypt() below does, and it is the accepted
  answer for "Using ECC, encrypt the message ...".

Library: pycryptodome (ECC, DSS) + hashlib for the key derivation.
Curve  : "P-256" is the same thing as secp256r1 / prime256v1.
"""

from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib


# ---------------------------------------------------------------------------
# KEY GENERATION
# ---------------------------------------------------------------------------

def ecc_generate(curve="P-256"):
    """Private key object; .public_key() gives the public half.
    Curves you may be asked for: P-256 (secp256r1), P-384, P-521."""
    return ECC.generate(curve=curve)


# ---------------------------------------------------------------------------
# ECDH : shared secret between two key pairs
# ---------------------------------------------------------------------------

def ecdh_shared_secret(my_private, their_public):
    """Shared point = my_private_scalar * their_public_point.
    Both sides get the SAME x coordinate -> hash it to make an AES key."""
    point = their_public.pointQ * my_private.d
    # size_in_bytes() adapts to the curve (32 for P-256, 66 for P-521)
    x_bytes = int(point.x).to_bytes(point.size_in_bytes(), "big")
    return hashlib.sha256(x_bytes).digest()       # 32-byte symmetric key


# ---------------------------------------------------------------------------
# ECIES : "encrypt a message using ECC"
# ---------------------------------------------------------------------------

def ecc_encrypt(message, recipient_public):
    """Returns (ephemeral_public_pem, nonce, tag, ciphertext)."""
    data = message.encode() if isinstance(message, str) else message
    eph = ECC.generate(curve=recipient_public.curve)      # one-time key pair
    key = ecdh_shared_secret(eph, recipient_public)       # shared AES key
    cipher = AES.new(key, AES.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(data)
    return eph.public_key().export_key(format="PEM"), cipher.nonce, tag, ct


def ecc_decrypt(eph_pub_pem, nonce, tag, ct, my_private):
    eph_pub = ECC.import_key(eph_pub_pem)
    key = ecdh_shared_secret(my_private, eph_pub)         # same shared secret
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)


# ---------------------------------------------------------------------------
# ECDSA : digital signature on an elliptic curve
# ---------------------------------------------------------------------------

def ecc_sign(message, private_key):
    data = message.encode() if isinstance(message, str) else message
    h = SHA256.new(data)
    return DSS.new(private_key, "fips-186-3").sign(h)


def ecc_verify(message, signature, public_key):
    data = message.encode() if isinstance(message, str) else message
    h = SHA256.new(data)
    try:
        DSS.new(public_key, "fips-186-3").verify(h, signature)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# RAW ELLIPTIC CURVE MATHS (when a question wants the point arithmetic shown)
#   curve:  y^2 = x^3 + a*x + b  (mod p)
# ---------------------------------------------------------------------------

def point_add(P, Q, a, p):
    """Add two points on the curve. None represents the point at infinity."""
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None                                   # P + (-P) = infinity
    if P == Q:
        lam = (3 * x1 * x1 + a) * pow(2 * y1, -1, p) % p   # tangent slope
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, p) % p          # chord slope
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)


def point_multiply(k, P, a, p):
    """Scalar multiply k*P by double-and-add (this IS the ECC 'hard problem')."""
    result, addend = None, P
    while k:
        if k & 1:
            result = point_add(result, addend, a, p)
        addend = point_add(addend, addend, a, p)
        k >>= 1
    return result


# small demo curve so you can print real numbers in an exam
DEMO_CURVE = dict(p=97, a=2, b=3, G=(3, 6), n=5)


if __name__ == "__main__":
    alice = ecc_generate()
    blob = ecc_encrypt("Secure Transactions", alice.public_key())
    print("ECC decrypt:", ecc_decrypt(*blob, alice).decode())

    sig = ecc_sign("invoice#42", alice)
    print("ECDSA ok   :", ecc_verify("invoice#42", sig, alice.public_key()),
          "| tampered:", ecc_verify("invoice#43", sig, alice.public_key()))

    bob = ecc_generate()
    s1 = ecdh_shared_secret(alice, bob.public_key())
    s2 = ecdh_shared_secret(bob, alice.public_key())
    print("ECDH match :", s1 == s2)

    c = DEMO_CURVE
    print("raw 3*G    :", point_multiply(3, c["G"], c["a"], c["p"]))
