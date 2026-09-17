"""
LAB 4 - EXERCISE 2 : HealthCare Inc. - Rabin key management service

The question asks for a centralized KMS with:
  * key generation (Rabin, configurable size e.g. 1024 bits)
  * key distribution (an API to request keys)
  * key revocation
  * key renewal (every 12 months)
  * secure storage of private keys
  * auditing and logging
  * regulatory compliance notes (HIPAA)
  * a trade-off analysis Rabin vs RSA

RABIN RECAP
  primes p, q with p = q = 3 (mod 4)      public key n = p*q
  encrypt : c = m^2 mod n                 (one squaring - very fast)
  decrypt : four square roots via CRT; a redundancy marker picks the right one

RUN: python q2.py demo     (or no argument for the menu)
"""

import os
import json
import random
import hashlib
import base64
from datetime import datetime, timedelta

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

STORE = "rabin_kms_store"
MARKER = b"##"                      # redundancy used to pick the right root


# ===========================================================================
# RABIN PRIMITIVES
# ===========================================================================
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


def blum_prime(bits):
    """Prime p with p = 3 (mod 4) - makes square roots easy to compute."""
    while True:
        c = random.getrandbits(bits) | (1 << (bits - 1)) | 3
        if c % 4 == 3 and is_prime(c):
            return c


def rabin_keygen(bits=1024):
    p = blum_prime(bits // 2)
    q = blum_prime(bits // 2)
    while q == p:
        q = blum_prime(bits // 2)
    return p * q, (p, q)


def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x, y = egcd(b, a % b)
    return (g, y, x - (a // b) * y)


def rabin_encrypt(message, n):
    data = message.encode() if isinstance(message, str) else message
    m = int.from_bytes(data + MARKER, "big")
    if m >= n:
        raise ValueError("message too long for this key size")
    return pow(m, 2, n)


def rabin_decrypt(c, p, q):
    """Compute the four roots via CRT, return the one carrying the marker."""
    n = p * q
    mp = pow(c, (p + 1) // 4, p)
    mq = pow(c, (q + 1) // 4, q)
    _, yp, yq = egcd(p, q)
    r1 = (yp * p * mq + yq * q * mp) % n
    r3 = (yp * p * mq - yq * q * mp) % n
    for r in (r1, n - r1, r3, n - r3):
        b = r.to_bytes((r.bit_length() + 7) // 8 or 1, "big")
        if b.endswith(MARKER):
            return b[:-2]
    return None


# ===========================================================================
# SECURE STORAGE : private keys encrypted with a master password
# ===========================================================================
def seal(data, password):
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32, count=100_000)   # slow on purpose
    c = AES.new(key, AES.MODE_GCM)
    ct, tag = c.encrypt_and_digest(data)
    return salt + c.nonce + tag + ct


def unseal(blob, password):
    salt, nonce, tag, ct = blob[:16], blob[16:32], blob[32:48], blob[48:]
    key = PBKDF2(password, salt, dkLen=32, count=100_000)
    return AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)


# ===========================================================================
# THE KEY MANAGEMENT SERVICE
# ===========================================================================
class RabinKMS:

    def __init__(self, master_password="hospital-master-key", key_bits=1024,
                 renew_months=12, store=STORE):
        self.pw = master_password
        self.bits = key_bits
        self.renew_after = timedelta(days=30 * renew_months)
        self.store = store
        os.makedirs(store, exist_ok=True)
        self.registry = {}
        self.logfile = os.path.join(store, "audit.log")

    # --- auditing ---------------------------------------------------------
    def log(self, actor, action, detail=""):
        line = (f"{datetime.now().isoformat(timespec='seconds')} | "
                f"{actor:<18} | {action:<18} | {detail}")
        with open(self.logfile, "a") as f:
            f.write(line + "\n")
        print("  LOG:", line)

    # --- 1. generation ----------------------------------------------------
    def generate(self, facility):
        n, (p, q) = rabin_keygen(self.bits)
        blob = seal(json.dumps({"p": str(p), "q": str(q)}).encode(), self.pw)
        with open(os.path.join(self.store, f"{facility}.key"), "wb") as f:
            f.write(blob)                          # PRIVATE key, encrypted
        self.registry[facility] = {
            "n": str(n), "bits": self.bits, "revoked": False,
            "created": datetime.now().isoformat(timespec="seconds"),
            "renew_due": (datetime.now() + self.renew_after).isoformat(timespec="seconds"),
        }
        self.log(facility, "KEY_GENERATED", f"Rabin {self.bits}-bit")
        return n

    # --- 2. distribution --------------------------------------------------
    def get_public_key(self, facility):
        self._active(facility)
        self.log(facility, "PUBLIC_KEY_ISSUED")
        return int(self.registry[facility]["n"])

    def get_private_key(self, facility, password):
        """Only released against the master password."""
        self._active(facility)
        with open(os.path.join(self.store, f"{facility}.key"), "rb") as f:
            d = json.loads(unseal(f.read(), password))
        self.log(facility, "PRIVATE_KEY_ISSUED", "master password verified")
        return int(d["p"]), int(d["q"])

    # --- 3. revocation ----------------------------------------------------
    def revoke(self, facility, reason):
        self.registry[facility]["revoked"] = True
        self.log(facility, "KEY_REVOKED", reason)

    # --- 4. renewal -------------------------------------------------------
    def renew(self, facility):
        self.generate(facility)
        self.registry[facility]["revoked"] = False
        self.log(facility, "KEY_RENEWED", "12-month rotation")

    def renew_due(self):
        """Call periodically; renews anything past its 12-month mark."""
        out = []
        for f, m in list(self.registry.items()):
            if datetime.fromisoformat(m["renew_due"]) <= datetime.now():
                self.renew(f)
                out.append(f)
        return out

    def _active(self, facility):
        if facility not in self.registry:
            raise KeyError(f"{facility} has no keys")
        if self.registry[facility]["revoked"]:
            raise PermissionError(f"{facility}'s key is REVOKED")

    def status(self):
        print(f"  {'facility':<20}{'bits':<7}{'revoked':<9}{'renew due'}")
        for f, m in self.registry.items():
            print(f"  {f:<20}{m['bits']:<7}{str(m['revoked']):<9}{m['renew_due']}")


TRADEOFF = """
=== TRADE-OFF ANALYSIS : RABIN vs RSA ===

SECURITY BASIS
  Rabin : finding square roots mod n - PROVABLY as hard as factoring n.
  RSA   : the RSA problem - believed hard, but not proven equivalent to
          factoring. So Rabin has the stronger theoretical guarantee.

ENCRYPTION SPEED
  Rabin : ONE modular squaring (c = m^2 mod n). The fastest public-key
          encryption there is.
  RSA   : m^e mod n with e = 65537 -> 17 squarings/multiplications.
  -> Rabin wins clearly.

DECRYPTION SPEED
  Both need work proportional to the key size. Rabin uses two exponentiations
  mod p and mod q plus a CRT combine - comparable to RSA with CRT.

THE AMBIGUITY PROBLEM
  Rabin decryption returns FOUR square roots; only one is the real message.
  You must add redundancy (a marker, a hash, or a length field) to pick it.
  RSA decryption is unambiguous. This is Rabin's main practical drawback.

CHOSEN-CIPHERTEXT ATTACK
  Plain Rabin is completely broken by a chosen-ciphertext attack: getting a
  second square root of a chosen value factors n immediately.
  Padding (OAEP-style) is therefore mandatory. RSA needs padding too, but a
  CCA against textbook RSA does not hand over the private key so directly.

SIGNATURES
  RSA signs naturally. Rabin signatures need a hash-and-retry loop because
  only a quarter of values are quadratic residues.

ADOPTION
  RSA is everywhere (TLS, PGP, smart cards) with mature libraries.
  Rabin has almost no deployment - in this lab it must be hand-implemented.

VERDICT FOR HEALTHCARE INC.
  Rabin's cheap encryption suits low-power devices that only ENCRYPT
  (sensors, bedside monitors). For a hospital-wide system that also needs
  signatures, certificates and library support, RSA (or better, ECC) is the
  practical choice; Rabin stays a specialised optimisation.

=== HIPAA / REGULATORY COMPLIANCE NOTES ===
  * private keys encrypted at rest with PBKDF2 + AES-GCM (this file)
  * every key operation written to an append-only audit log
  * automatic 12-month key rotation
  * immediate revocation when a facility closes or is compromised
  * access to private keys requires the master credential
  * logs retain who, what and when - enough for a compliance report
"""


def demo():
    import shutil
    shutil.rmtree(STORE, ignore_errors=True)
    kms = RabinKMS(key_bits=1024)

    print("=== 1. KEY GENERATION ===")
    for f in ("CityHospital", "RuralClinic", "ChildrensWard"):
        n = kms.generate(f)
        print(f"     {f}: n has {n.bit_length()} bits")

    print("\n=== 2. DISTRIBUTION + ENCRYPT/DECRYPT A PATIENT RECORD ===")
    n = kms.get_public_key("CityHospital")
    record = "Patient 4471 | diagnosis: hypertension | doctor: Dr Nair"
    c = rabin_encrypt(record, n)
    print("     ciphertext:", str(c)[:70], "...")
    p, q = kms.get_private_key("CityHospital", "hospital-master-key")
    print("     decrypted :", rabin_decrypt(c, p, q).decode())

    print("\n=== 3. WRONG MASTER PASSWORD ===")
    try:
        kms.get_private_key("CityHospital", "guess")
    except ValueError:
        print("     private key stays sealed (AES-GCM authentication failed)")

    print("\n=== 4. REVOCATION ===")
    kms.revoke("RuralClinic", "facility closed")
    try:
        kms.get_public_key("RuralClinic")
    except PermissionError as e:
        print("     blocked:", e)

    print("\n=== 5. RENEWAL ===")
    kms.renew("RuralClinic")
    n2 = kms.get_public_key("RuralClinic")
    print("     new n bits:", n2.bit_length())

    print("\n=== 6. STATUS ===")
    kms.status()
    print(TRADEOFF)


def main():
    kms = RabinKMS(key_bits=1024)
    print("=== HealthCare Inc. Rabin Key Management Service ===")
    while True:
        print("\n1 generate  2 encrypt record  3 decrypt record  4 revoke"
              "  5 renew  6 status  7 trade-off analysis  8 full demo  0 exit")
        c = input("choice> ").strip()
        try:
            if c == "1":
                kms.generate(input("  facility: ").strip())
            elif c == "2":
                f = input("  facility: ").strip()
                rec = input("  record: ")
                print("  ciphertext:", rabin_encrypt(rec, kms.get_public_key(f)))
            elif c == "3":
                f = input("  facility: ").strip()
                ct = int(input("  ciphertext: "))
                p, q = kms.get_private_key(f, input("  master password: "))
                print("  plaintext:", rabin_decrypt(ct, p, q).decode())
            elif c == "4":
                kms.revoke(input("  facility: ").strip(), input("  reason: "))
            elif c == "5":
                kms.renew(input("  facility: ").strip())
            elif c == "6":
                kms.status()
            elif c == "7":
                print(TRADEOFF)
            elif c == "8":
                demo()
            elif c == "0":
                return
        except Exception as e:
            print("  !", type(e).__name__, e)


if __name__ == "__main__":
    import sys
    demo() if len(sys.argv) > 1 and sys.argv[1] == "demo" else main()
