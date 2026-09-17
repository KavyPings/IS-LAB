"""
LAB 4 - ADDITIONAL 1 : DigiRights Inc. - ElGamal DRM system

Required features:
  * key generation (ElGamal master key pair, configurable size)
  * content encryption API for creators
  * key distribution to authorised customers
  * access control: limited-time access, revocation, creator-owned content
  * key revocation (emergency)
  * key renewal every 24 months
  * secure storage of the master private key
  * auditing and logging

RUN: python q1.py demo   (or no argument for the menu)
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

STORE = "digirights_store"


# ===================== ElGamal primitives ==================================
def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x, y = egcd(b, a % b)
    return (g, y, x - (a // b) * y)


def modinv(a, m):
    return egcd(a % m, m)[1] % m


def is_prime(n, k=16):
    if n < 2:
        return False
    for sp in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31):
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


def safe_prime(bits):
    """p = 2q + 1 with q prime, so g = 2 generates a big subgroup."""
    while True:
        q = random.getrandbits(bits - 1) | (1 << (bits - 2)) | 1
        if is_prime(q) and is_prime(2 * q + 1):
            return 2 * q + 1


def elgamal_keygen(bits=256):
    """NOTE: the question says 2048 bits. Generating a 2048-bit SAFE prime
    takes several minutes, so the demo uses 256. Pass bits=2048 if you have
    the time - nothing else changes."""
    p = safe_prime(bits)
    g = 2
    x = random.randrange(2, p - 2)
    return (p, g, pow(g, x, p)), x


def elgamal_wrap(aes_key_int, pub):
    """Encrypt the AES content key under the master public key."""
    p, g, h = pub
    k = random.randrange(2, p - 2)
    return pow(g, k, p), (aes_key_int * pow(h, k, p)) % p


def elgamal_unwrap(c1, c2, x, p):
    s = pow(c1, x, p)
    return (c2 * modinv(s, p)) % p


# ===================== secure storage ======================================
def seal(data, password):
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32, count=100_000)
    c = AES.new(key, AES.MODE_GCM)
    ct, tag = c.encrypt_and_digest(data)
    return salt + c.nonce + tag + ct


def unseal(blob, password):
    salt, nonce, tag, ct = blob[:16], blob[16:32], blob[32:48], blob[48:]
    key = PBKDF2(password, salt, dkLen=32, count=100_000)
    return AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)


# ===================== the DRM service =====================================
class DigiRightsDRM:

    def __init__(self, master_password="drm-master", bits=256, store=STORE):
        os.makedirs(store, exist_ok=True)
        self.store = store
        self.pw = master_password
        self.bits = bits
        self.pub, x = elgamal_keygen(bits)
        self._seal_private(x)
        self.content = {}              # id -> dict
        self.grants = {}               # (customer, content_id) -> expiry
        self.revoked_master = False
        self.created = datetime.now()
        self.renew_due = self.created + timedelta(days=730)   # 24 months
        self.logs = []
        self.log("SYSTEM", "MASTER_KEY_GENERATED", f"ElGamal {bits}-bit")

    # --- storage of the master private key --------------------------------
    def _seal_private(self, x):
        with open(os.path.join(self.store, "master.key"), "wb") as f:
            f.write(seal(str(x).encode(), self.pw))

    def _open_private(self, password):
        with open(os.path.join(self.store, "master.key"), "rb") as f:
            return int(unseal(f.read(), password))

    # --- auditing ---------------------------------------------------------
    def log(self, actor, action, detail=""):
        line = (f"{datetime.now().isoformat(timespec='seconds')} | {actor:<14}"
                f" | {action:<22} | {detail}")
        self.logs.append(line)
        with open(os.path.join(self.store, "audit.log"), "a") as f:
            f.write(line + "\n")

    # --- content creators -------------------------------------------------
    def upload(self, creator, title, data):
        """Content is AES-encrypted; the AES key is wrapped with ElGamal."""
        if self.revoked_master:
            raise PermissionError("master key revoked - uploads suspended")
        aes_key = get_random_bytes(16)                # AES-128 content key
        c = AES.new(aes_key, AES.MODE_GCM)
        ct, tag = c.encrypt_and_digest(data.encode())
        c1, c2 = elgamal_wrap(int.from_bytes(aes_key, "big"), self.pub)
        cid = len(self.content) + 1
        self.content[cid] = {"title": title, "creator": creator, "c1": c1,
                             "c2": c2, "nonce": c.nonce, "tag": tag, "ct": ct,
                             "uploaded": datetime.now().isoformat(timespec="seconds")}
        self.log(creator, "CONTENT_UPLOADED", f"#{cid} {title}")
        return cid

    # --- access control ---------------------------------------------------
    def grant(self, actor, customer, cid, hours=24):
        """Only the creator (or ADMIN) may grant access to their content."""
        item = self.content[cid]
        if actor not in (item["creator"], "ADMIN"):
            raise PermissionError(f"{actor} does not own content #{cid}")
        self.grants[(customer, cid)] = datetime.now() + timedelta(hours=hours)
        self.log(actor, "ACCESS_GRANTED", f"{customer} -> #{cid} for {hours}h")

    def revoke_access(self, actor, customer, cid):
        item = self.content[cid]
        if actor not in (item["creator"], "ADMIN"):
            raise PermissionError(f"{actor} does not own content #{cid}")
        self.grants.pop((customer, cid), None)
        self.log(actor, "ACCESS_REVOKED", f"{customer} -> #{cid}")

    def has_access(self, customer, cid):
        exp = self.grants.get((customer, cid))
        return exp is not None and datetime.now() < exp

    # --- playback ---------------------------------------------------------
    def play(self, customer, cid, password):
        if self.revoked_master:
            raise PermissionError("master key revoked - playback disabled")
        if not self.has_access(customer, cid):
            raise PermissionError(f"{customer} has no valid licence for #{cid}")
        item = self.content[cid]
        x = self._open_private(password)
        key_int = elgamal_unwrap(item["c1"], item["c2"], x, self.pub[0])
        aes_key = key_int.to_bytes(16, "big")
        data = AES.new(aes_key, AES.MODE_GCM,
                       nonce=item["nonce"]).decrypt_and_verify(item["ct"], item["tag"])
        self.log(customer, "CONTENT_PLAYED", f"#{cid} {item['title']}")
        return data.decode()

    # --- emergency / rotation ---------------------------------------------
    def revoke_master(self, reason):
        self.revoked_master = True
        self.log("ADMIN", "MASTER_KEY_REVOKED", reason)

    def renew_master(self):
        """New key pair -> all existing content must be re-wrapped."""
        old_x = self._open_private(self.pw)
        old_p = self.pub[0]
        self.pub, x = elgamal_keygen(self.bits)
        self._seal_private(x)
        for cid, item in self.content.items():       # re-wrap every AES key
            key_int = elgamal_unwrap(item["c1"], item["c2"], old_x, old_p)
            item["c1"], item["c2"] = elgamal_wrap(key_int, self.pub)
        self.revoked_master = False
        self.renew_due = datetime.now() + timedelta(days=730)
        self.log("ADMIN", "MASTER_KEY_RENEWED", f"{len(self.content)} items re-wrapped")

    def status(self):
        print(f"  master key    : ElGamal {self.bits}-bit, p has "
              f"{self.pub[0].bit_length()} bits")
        print(f"  revoked       : {self.revoked_master}")
        print(f"  renewal due   : {self.renew_due.date()}")
        print(f"  content items : {len(self.content)}")
        for cid, i in self.content.items():
            print(f"     #{cid} {i['title']:<22} by {i['creator']:<10} {i['uploaded']}")
        print("  active licences:")
        for (cust, cid), exp in self.grants.items():
            state = "valid" if datetime.now() < exp else "EXPIRED"
            print(f"     {cust:<10} -> #{cid}  until {exp:%Y-%m-%d %H:%M}  [{state}]")


def demo():
    import shutil
    shutil.rmtree(STORE, ignore_errors=True)
    drm = DigiRightsDRM(bits=256)

    print("=== 1. CONTENT UPLOAD (encrypted with master public key) ===")
    m1 = drm.upload("studioA", "Movie: Dune III", "MOVIE-BITSTREAM-AAA...")
    b1 = drm.upload("authorB", "Ebook: Crypto 101", "EBOOK-CONTENT-BBB...")
    print(f"    uploaded #{m1} and #{b1}")

    print("\n=== 2. ACCESS CONTROL ===")
    drm.grant("studioA", "customer1", m1, hours=2)
    print("    customer1 plays #1:", drm.play("customer1", m1, "drm-master"))
    try:
        drm.play("customer1", b1, "drm-master")
    except PermissionError as e:
        print("    blocked:", e)

    print("\n=== 3. A CREATOR CANNOT GRANT SOMEONE ELSE'S CONTENT ===")
    try:
        drm.grant("studioA", "customer2", b1)
    except PermissionError as e:
        print("    blocked:", e)

    print("\n=== 4. REVOKING A CUSTOMER'S ACCESS ===")
    drm.revoke_access("studioA", "customer1", m1)
    try:
        drm.play("customer1", m1, "drm-master")
    except PermissionError as e:
        print("    blocked:", e)

    print("\n=== 5. EXPIRED (TIME-LIMITED) LICENCE ===")
    drm.grant("authorB", "customer2", b1, hours=0)          # already expired
    try:
        drm.play("customer2", b1, "drm-master")
    except PermissionError as e:
        print("    blocked:", e)

    print("\n=== 6. EMERGENCY MASTER KEY REVOCATION ===")
    drm.grant("studioA", "customer1", m1, hours=5)
    drm.revoke_master("private key suspected leaked")
    try:
        drm.play("customer1", m1, "drm-master")
    except PermissionError as e:
        print("    blocked:", e)

    print("\n=== 7. KEY RENEWAL (24-month rotation, content re-wrapped) ===")
    drm.renew_master()
    print("    customer1 plays #1 again:", drm.play("customer1", m1, "drm-master"))

    print("\n=== 8. STATUS ===")
    drm.status()

    print("\n=== 9. AUDIT LOG ===")
    for line in drm.logs:
        print("   ", line)


def main():
    drm = DigiRightsDRM(bits=256)
    print("=== DigiRights DRM (ElGamal) ===")
    while True:
        print("\n1 upload  2 grant  3 play  4 revoke access  5 revoke master"
              "  6 renew master  7 status  8 audit  9 demo  0 exit")
        c = input("choice> ").strip()
        try:
            if c == "1":
                print("  content id:", drm.upload(input("  creator: ").strip(),
                                                  input("  title: "),
                                                  input("  content: ")))
            elif c == "2":
                drm.grant(input("  creator: ").strip(), input("  customer: ").strip(),
                          int(input("  content id: ")), int(input("  hours: ") or 24))
            elif c == "3":
                print("  ", drm.play(input("  customer: ").strip(),
                                     int(input("  content id: ")),
                                     input("  master password: ")))
            elif c == "4":
                drm.revoke_access(input("  creator: ").strip(),
                                  input("  customer: ").strip(),
                                  int(input("  content id: ")))
            elif c == "5":
                drm.revoke_master(input("  reason: "))
            elif c == "6":
                drm.renew_master()
            elif c == "7":
                drm.status()
            elif c == "8":
                for l in drm.logs:
                    print("   ", l)
            elif c == "9":
                demo()
            elif c == "0":
                return
        except Exception as e:
            print("  !", type(e).__name__, e)


if __name__ == "__main__":
    import sys
    demo() if len(sys.argv) > 1 and sys.argv[1] == "demo" else main()
