"""
LAB 3 - ADDITIONAL 2
Using ECC, encrypt "Secure Transactions" with the public key and decrypt
with the private key.

Same as exercise 2, but written as REUSABLE FUNCTIONS with a menu, and
comparing two curves. Use this version when the question is open-ended.
"""

import hashlib
import time
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES

MESSAGE = "Secure Transactions"


def derive_key(private_key, public_key):
    """ECDH shared secret -> SHA-256 -> 32-byte AES key."""
    shared_point = public_key.pointQ * private_key.d
    # size_in_bytes() adapts to the curve (32 for P-256, 66 for P-521)
    return hashlib.sha256(int(shared_point.x).to_bytes(shared_point.size_in_bytes(), "big")).digest()


def ecc_encrypt(message, recipient_public):
    """ECIES. Returns everything the recipient needs."""
    ephemeral = ECC.generate(curve=recipient_public.curve)
    key = derive_key(ephemeral, recipient_public)
    cipher = AES.new(key, AES.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(message.encode())
    return {"eph_pub": ephemeral.public_key(), "nonce": cipher.nonce,
            "tag": tag, "ct": ct}


def ecc_decrypt(blob, private_key):
    key = derive_key(private_key, blob["eph_pub"])
    return AES.new(key, AES.MODE_EAX,
                   nonce=blob["nonce"]).decrypt_and_verify(blob["ct"],
                                                           blob["tag"]).decode()


if __name__ == "__main__":
    for curve in ("P-256", "P-384", "P-521"):
        t0 = time.perf_counter()
        key = ECC.generate(curve=curve)
        t_kg = time.perf_counter() - t0

        t0 = time.perf_counter()
        blob = ecc_encrypt(MESSAGE, key.public_key())
        t_enc = time.perf_counter() - t0

        t0 = time.perf_counter()
        out = ecc_decrypt(blob, key)
        t_dec = time.perf_counter() - t0

        print(f"\n--- {curve} ---")
        print(f"  keygen  : {t_kg*1000:7.2f} ms")
        print(f"  encrypt : {t_enc*1000:7.2f} ms")
        print(f"  decrypt : {t_dec*1000:7.2f} ms")
        print(f"  cipher  : {blob['ct'].hex()}")
        print(f"  plain   : {out}")
        print(f"  correct : {out == MESSAGE}")

    print("\nsmaller curve = faster, but less security margin.")
    print("P-256 is the standard choice (secp256r1) for most systems.")
