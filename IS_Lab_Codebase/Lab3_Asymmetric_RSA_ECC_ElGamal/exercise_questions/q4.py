"""
LAB 3 - EXERCISE 4
Secure file transfer system using RSA-2048 and ECC (secp256r1).
Generate/exchange keys, encrypt and decrypt files of varying sizes
(1 MB, 10 MB), measure key generation time, encryption/decryption speed
and overhead, and document the findings.

KEY CONCEPT - WHY HYBRID ENCRYPTION
  RSA-2048 with OAEP can only encrypt ~214 bytes. ECC cannot encrypt at all.
  So BOTH schemes are used the same way for files:
      generate a random AES-256 session key
      AES-encrypt the file (fast, any size)
      protect the session key with RSA (encrypt it) or ECC (ECDH-derive it)
  The asymmetric part therefore costs a FIXED amount no matter the file size.

NOTE: file sizes are set to 1 MB and 4 MB by default so the script finishes
quickly. Change SIZES_MB below to [1, 10] for the full question.
"""

import os
import time
import hashlib
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

SIZES_MB = [1, 4]           # set to [1, 10] for the exact question


def timed(fn, *a, **k):
    """Run once, return (result, seconds)."""
    t0 = time.perf_counter()
    r = fn(*a, **k)
    return r, time.perf_counter() - t0


# ---------------------------------------------------------------- RSA path
def rsa_encrypt_file(data, public_key):
    session = get_random_bytes(32)                       # AES-256 key
    c = AES.new(session, AES.MODE_GCM)
    ct, tag = c.encrypt_and_digest(data)                 # bulk encryption
    enc_key = PKCS1_OAEP.new(public_key).encrypt(session)  # protect the key
    return enc_key, c.nonce, tag, ct


def rsa_decrypt_file(enc_key, nonce, tag, ct, private_key):
    session = PKCS1_OAEP.new(private_key).decrypt(enc_key)
    return AES.new(session, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)


# ---------------------------------------------------------------- ECC path
def ecdh(priv, pub):
    point = pub.pointQ * priv.d
    return hashlib.sha256(int(point.x).to_bytes(point.size_in_bytes(), "big")).digest()


def ecc_encrypt_file(data, recipient_public):
    eph = ECC.generate(curve=recipient_public.curve)     # ephemeral key pair
    session = ecdh(eph, recipient_public)                # derived AES key
    c = AES.new(session, AES.MODE_GCM)
    ct, tag = c.encrypt_and_digest(data)
    return eph.public_key(), c.nonce, tag, ct


def ecc_decrypt_file(eph_pub, nonce, tag, ct, my_private):
    session = ecdh(my_private, eph_pub)
    return AES.new(session, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)


if __name__ == "__main__":
    print("=== KEY GENERATION ===")
    rsa_key, t_rsa_kg = timed(RSA.generate, 2048)
    ecc_key, t_ecc_kg = timed(ECC.generate, curve="P-256")
    print(f"  RSA-2048 key generation : {t_rsa_kg*1000:9.2f} ms")
    print(f"  ECC P-256 key generation: {t_ecc_kg*1000:9.2f} ms")
    print(f"  -> ECC is ~{t_rsa_kg/max(t_ecc_kg,1e-9):.0f}x faster to generate")

    print("\n  key/ciphertext sizes")
    print(f"  RSA public key PEM : {len(rsa_key.publickey().export_key())} bytes")
    print(f"  ECC public key PEM : {len(ecc_key.public_key().export_key(format='PEM'))} bytes")

    print("\n=== FILE ENCRYPTION / DECRYPTION ===")
    print(f"  {'size':<8}{'scheme':<10}{'encrypt s':>12}{'decrypt s':>12}"
          f"{'MB/s enc':>11}{'overhead B':>12}")
    for mb in SIZES_MB:
        data = os.urandom(mb * 1024 * 1024)              # random file content

        blob, te = timed(rsa_encrypt_file, data, rsa_key.publickey())
        out, td = timed(rsa_decrypt_file, *blob, rsa_key)
        assert out == data
        overhead = len(blob[0]) + len(blob[1]) + len(blob[2])
        print(f"  {mb:<3}MB   {'RSA-2048':<10}{te:>12.4f}{td:>12.4f}"
              f"{mb/te:>11.1f}{overhead:>12}")

        blob, te = timed(ecc_encrypt_file, data, ecc_key.public_key())
        out, td = timed(ecc_decrypt_file, *blob, ecc_key)
        assert out == data
        overhead = len(blob[0].export_key(format="DER")) + len(blob[1]) + len(blob[2])
        print(f"  {mb:<3}MB   {'ECC P-256':<10}{te:>12.4f}{td:>12.4f}"
              f"{mb/te:>11.1f}{overhead:>12}")

    print("""
=== FINDINGS / DOCUMENTATION ===

KEY SIZE
  RSA-2048 and ECC P-256 give roughly the same security level (~112 bits),
  but the ECC key is 8x smaller. For 128-bit security RSA needs 3072 bits
  while ECC needs only 256.

KEY GENERATION
  RSA must search for two large random primes - slow and variable.
  ECC just picks a random scalar - almost instant and constant time.

ENCRYPTION / DECRYPTION SPEED
  Both are dominated by AES on the bulk data, so the MB/s figures are
  nearly identical. The asymmetric step is a fixed cost:
     RSA encrypt (public, small e=65537) is fast; RSA decrypt (private) is slow.
     ECC needs one point multiplication on each side - fast and symmetric.

STORAGE / BANDWIDTH OVERHEAD
  RSA adds a 256-byte encrypted session key per file.
  ECC adds a ~91-byte ephemeral public key. ECC wins on bandwidth.

RESISTANCE TO ATTACKS
  RSA breaks if factoring gets easier, or if primes are weak/close
  (see Lab 4 - Fermat factorisation).
  ECC breaks only if the discrete log on the curve is solved; the risk is
  using a badly chosen curve or a repeated nonce.
  BOTH are broken by a large quantum computer (Shor's algorithm).

CONCLUSION FOR FILE TRANSFER
  ECC (ECDH + AES-GCM) is the better choice: smaller keys, faster key
  generation, less overhead per file, same bulk speed. RSA remains useful
  where existing certificates and infrastructure already use it.
""")
