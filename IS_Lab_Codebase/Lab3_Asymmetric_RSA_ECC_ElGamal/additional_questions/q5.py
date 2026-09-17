"""
LAB 3 - ADDITIONAL 5
Government agency study: implement RSA (2048-bit), ElGamal (secp256r1 /
EC-ElGamal) and ECC, measure key generation, encryption and decryption time
for messages of various sizes (1 KB, 10 KB), and compare efficiency.

All three are used in HYBRID mode (asymmetric protects an AES key) because
none of them can encrypt kilobytes directly.
"""

import time
import hashlib
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

SIZES = {"1 KB": 1024, "10 KB": 10 * 1024, "100 KB": 100 * 1024}


def t(fn, *a, **k):
    t0 = time.perf_counter()
    r = fn(*a, **k)
    return r, (time.perf_counter() - t0) * 1000       # milliseconds


# ------------------------------------------------------------------ RSA
def rsa_enc(data, pub):
    sk = get_random_bytes(32)
    c = AES.new(sk, AES.MODE_GCM)
    ct, tag = c.encrypt_and_digest(data)
    return PKCS1_OAEP.new(pub).encrypt(sk), c.nonce, tag, ct


def rsa_dec(ek, nonce, tag, ct, priv):
    sk = PKCS1_OAEP.new(priv).decrypt(ek)
    return AES.new(sk, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)


# ------------------------------------------------------- ECC / EC-ElGamal
def ec_shared(priv_scalar_key, pub):
    pt = pub.pointQ * priv_scalar_key.d
    return hashlib.sha256(int(pt.x).to_bytes(pt.size_in_bytes(), "big")).digest()


def ec_enc(data, pub):
    eph = ECC.generate(curve=pub.curve)
    c = AES.new(ec_shared(eph, pub), AES.MODE_GCM)
    ct, tag = c.encrypt_and_digest(data)
    return eph.public_key(), c.nonce, tag, ct


def ec_dec(eph_pub, nonce, tag, ct, priv):
    return AES.new(ec_shared(priv, eph_pub), AES.MODE_GCM,
                   nonce=nonce).decrypt_and_verify(ct, tag)


if __name__ == "__main__":
    print("=== KEY GENERATION ===")
    rsa_key, t_rsa = t(RSA.generate, 2048)
    ecc_key, t_ecc = t(ECC.generate, curve="P-256")
    eg_key, t_eg = t(ECC.generate, curve="P-256")     # EC-ElGamal uses the same curve
    print(f"  RSA-2048          : {t_rsa:8.2f} ms")
    print(f"  ECC P-256         : {t_ecc:8.2f} ms")
    print(f"  EC-ElGamal P-256  : {t_eg:8.2f} ms")

    print("\n=== ENCRYPT / DECRYPT ===")
    print(f"  {'size':<8}{'scheme':<20}{'encrypt ms':>12}{'decrypt ms':>12}{'overhead B':>12}")
    for label, n in SIZES.items():
        data = get_random_bytes(n)

        blob, te = t(rsa_enc, data, rsa_key.publickey())
        out, td = t(rsa_dec, *blob, rsa_key)
        assert out == data
        print(f"  {label:<8}{'RSA-2048':<20}{te:>12.3f}{td:>12.3f}"
              f"{len(blob[0])+len(blob[1])+len(blob[2]):>12}")

        blob, te = t(ec_enc, data, ecc_key.public_key())
        out, td = t(ec_dec, *blob, ecc_key)
        assert out == data
        oh = len(blob[0].export_key(format="DER")) + len(blob[1]) + len(blob[2])
        print(f"  {label:<8}{'ECC (ECIES) P-256':<20}{te:>12.3f}{td:>12.3f}{oh:>12}")

        blob, te = t(ec_enc, data, eg_key.public_key())
        out, td = t(ec_dec, *blob, eg_key)
        assert out == data
        oh = len(blob[0].export_key(format="DER")) + len(blob[1]) + len(blob[2])
        print(f"  {label:<8}{'EC-ElGamal P-256':<20}{te:>12.3f}{td:>12.3f}{oh:>12}")
        print()

    print("""=== COMPARISON / CONCLUSION ===

KEY GENERATION
  RSA is 50-100x slower (it must find two large random primes).
  ECC and EC-ElGamal only pick a random scalar.

ENCRYPTION
  RSA encryption is cheap (public exponent 65537 = 17 bits).
  EC schemes need one scalar multiplication - slightly more, still ~1 ms.

DECRYPTION
  RSA decryption is EXPENSIVE (full 2048-bit private exponent).
  EC decryption is one scalar multiplication - much faster.

OVERHEAD PER MESSAGE
  RSA-2048 : 256 bytes of encrypted session key
  EC P-256 : ~91 bytes of ephemeral public key

SECURITY
  Equivalent level: RSA-2048 ~ ECC-256 ~ 112-bit symmetric security.
  ElGamal (and EC-ElGamal) are randomised, so encrypting the same message
  twice gives different ciphertexts - RSA needs OAEP to get this property.

RECOMMENDATION FOR THE AGENCY
  Use ECC/EC-ElGamal for new systems: faster key generation, faster
  decryption, smaller keys and smaller messages. Keep RSA only for
  compatibility with existing certificates.""")
