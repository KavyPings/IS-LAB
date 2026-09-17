"""
LAB 4 - SAMPLE / SCENARIO QUESTION (exam style practice)

"CampusVault is a university-wide key service. It must
   - issue RSA key pairs to departments,
   - store private keys encrypted with a master password,
   - let departments exchange signed + encrypted documents,
   - enforce roles: ADMIN can generate/revoke/renew any key,
     a DEPARTMENT can only use its own key,
     an AUDITOR can only read the log,
   - rotate keys on demand and revoke compromised ones,
   - log every operation with a timestamp.
 Write a menu-driven Python program."

This combines EVERY Lab 4 idea: key management + access control + signing.
It is the closest practice question to the mid-term paper.
"""

import os
import json
import base64
import hashlib
from datetime import datetime, timedelta

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

STORE = "campusvault"
MASTER_PW = "campus-master-2026"

ROLES = {
    "admin":      {"generate", "revoke", "renew", "send", "receive", "log", "status"},
    "department": {"send", "receive", "status"},
    "auditor":    {"log", "status"},
}


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# --- secure storage --------------------------------------------------------
def seal(data, password):
    salt = get_random_bytes(16)
    k = PBKDF2(password, salt, dkLen=32, count=100_000)
    c = AES.new(k, AES.MODE_GCM)
    ct, tag = c.encrypt_and_digest(data)
    return salt + c.nonce + tag + ct


def unseal(blob, password):
    salt, nonce, tag, ct = blob[:16], blob[16:32], blob[32:48], blob[48:]
    k = PBKDF2(password, salt, dkLen=32, count=100_000)
    return AES.new(k, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)


class CampusVault:

    def __init__(self):
        os.makedirs(STORE, exist_ok=True)
        self.registry = {}
        self.logs = []
        self.session = None                     # (username, role)

    # --- access control ---------------------------------------------------
    def login(self, user, role):
        if role not in ROLES:
            print("  ! unknown role"); return False
        self.session = (user, role)
        self.log(user, "LOGIN", role)
        return True

    def require(self, action):
        if self.session is None:
            raise PermissionError("not logged in")
        user, role = self.session
        if action not in ROLES[role]:
            raise PermissionError(f"role '{role}' cannot '{action}'")

    def owns(self, dept):
        """A department may only touch its own key."""
        user, role = self.session
        if role != "admin" and user != dept:
            raise PermissionError(f"{user} may not act for {dept}")

    # --- auditing ---------------------------------------------------------
    def log(self, actor, action, detail=""):
        line = f"{now()} | {actor:<14} | {action:<16} | {detail}"
        self.logs.append(line)
        with open(os.path.join(STORE, "audit.log"), "a") as f:
            f.write(line + "\n")

    # --- key management ---------------------------------------------------
    def generate(self, dept, bits=2048):
        self.require("generate")
        key = RSA.generate(bits)
        with open(os.path.join(STORE, f"{dept}.key"), "wb") as f:
            f.write(seal(key.export_key(), MASTER_PW))     # sealed private key
        with open(os.path.join(STORE, f"{dept}.pub"), "wb") as f:
            f.write(key.publickey().export_key())
        self.registry[dept] = {
            "bits": bits, "revoked": False, "created": now(),
            "expires": (datetime.now() + timedelta(days=365)).strftime("%Y-%m-%d"),
            "fingerprint": hashlib.sha256(key.publickey().export_key()).hexdigest()[:16],
        }
        self.log(self.session[0], "KEY_GENERATED", f"{dept} {bits}-bit")

    def public(self, dept):
        m = self.registry.get(dept)
        if not m:
            raise KeyError(f"{dept} has no key")
        if m["revoked"]:
            raise PermissionError(f"{dept}'s key is revoked")
        with open(os.path.join(STORE, f"{dept}.pub"), "rb") as f:
            return RSA.import_key(f.read())

    def private(self, dept):
        self.owns(dept)
        m = self.registry.get(dept)
        if not m or m["revoked"]:
            raise PermissionError(f"{dept}'s key is unavailable")
        with open(os.path.join(STORE, f"{dept}.key"), "rb") as f:
            return RSA.import_key(unseal(f.read(), MASTER_PW))

    def revoke(self, dept, reason):
        self.require("revoke")
        self.registry[dept]["revoked"] = True
        self.log(self.session[0], "KEY_REVOKED", f"{dept}: {reason}")

    def renew(self, dept):
        self.require("renew")
        bits = self.registry[dept]["bits"]
        self.session = (self.session[0], "admin")
        self.generate(dept, bits)
        self.log(self.session[0], "KEY_RENEWED", dept)

    # --- messaging --------------------------------------------------------
    def send(self, sender, recipient, document):
        self.require("send")
        self.owns(sender)
        sig = pkcs1_15.new(self.private(sender)).sign(SHA256.new(document.encode()))
        sk = get_random_bytes(32)
        c = AES.new(sk, AES.MODE_GCM)
        ct, tag = c.encrypt_and_digest(document.encode())
        ek = PKCS1_OAEP.new(self.public(recipient)).encrypt(sk)
        pkt = {"from": sender, "to": recipient, "ek": ek, "nonce": c.nonce,
               "tag": tag, "ct": ct, "sig": sig, "ts": now()}
        self.log(sender, "DOC_SENT", f"-> {recipient}")
        return pkt

    def receive(self, pkt):
        self.require("receive")
        self.owns(pkt["to"])
        sk = PKCS1_OAEP.new(self.private(pkt["to"])).decrypt(pkt["ek"])
        doc = AES.new(sk, AES.MODE_GCM,
                      nonce=pkt["nonce"]).decrypt_and_verify(pkt["ct"], pkt["tag"])
        try:
            pkcs1_15.new(self.public(pkt["from"])).verify(SHA256.new(doc), pkt["sig"])
            ok = True
        except (ValueError, TypeError):
            ok = False
        self.log(pkt["to"], "DOC_RECEIVED", f"from {pkt['from']} sig={'ok' if ok else 'BAD'}")
        return doc.decode(), ok

    def status(self):
        self.require("status")
        print(f"  {'department':<14}{'bits':<7}{'revoked':<9}{'expires':<12}fingerprint")
        for d, m in self.registry.items():
            print(f"  {d:<14}{m['bits']:<7}{str(m['revoked']):<9}"
                  f"{m['expires']:<12}{m['fingerprint']}")


def demo():
    import shutil
    shutil.rmtree(STORE, ignore_errors=True)
    v = CampusVault()

    print("=== admin generates keys ===")
    v.login("registrar", "admin")
    for d in ("CSE", "ICT", "Exams"):
        v.generate(d, 2048)
    v.status()

    print("\n=== CSE sends a signed+encrypted document to Exams ===")
    v.login("CSE", "department")
    pkt = v.send("CSE", "Exams", "Internal marks sheet ICT3141 batch A2")
    v.login("Exams", "department")
    print("  received:", v.receive(pkt))

    print("\n=== a department cannot act for another ===")
    v.login("ICT", "department")
    try:
        v.send("CSE", "Exams", "forged memo")
    except PermissionError as e:
        print("  blocked:", e)

    print("\n=== a department cannot generate keys ===")
    try:
        v.generate("Physics")
    except PermissionError as e:
        print("  blocked:", e)

    print("\n=== auditor can only read the log ===")
    v.login("audit1", "auditor")
    try:
        v.send("ICT", "CSE", "x")
    except PermissionError as e:
        print("  blocked:", e)
    print("  log lines visible:", len(v.logs))

    print("\n=== admin revokes then renews ICT ===")
    v.login("registrar", "admin")
    v.revoke("ICT", "laptop stolen")
    try:
        v.public("ICT")
    except PermissionError as e:
        print("  blocked:", e)
    v.renew("ICT")
    v.status()

    print("\n=== audit log ===")
    for l in v.logs:
        print("   ", l)


def main():
    v = CampusVault()
    print("=== CampusVault key management service ===")
    u = input("username> ").strip()
    r = input("role (admin/department/auditor)> ").strip().lower()
    if not v.login(u, r):
        return
    while True:
        print("\n1 generate  2 status  3 send  4 revoke  5 renew  6 log"
              "  7 demo  0 exit")
        c = input("choice> ").strip()
        try:
            if c == "1":
                v.generate(input("  department: ").strip())
            elif c == "2":
                v.status()
            elif c == "3":
                s = input("  from: ").strip(); t = input("  to: ").strip()
                pkt = v.send(s, t, input("  document: "))
                print("  ciphertext:", pkt["ct"].hex()[:48], "...")
                v.session = (t, "department")
                print("  delivered :", v.receive(pkt))
                v.session = (u, r)
            elif c == "4":
                v.revoke(input("  department: ").strip(), input("  reason: "))
            elif c == "5":
                v.renew(input("  department: ").strip())
            elif c == "6":
                v.require("log")
                for l in v.logs:
                    print("   ", l)
            elif c == "7":
                demo()
            elif c == "0":
                return
        except Exception as e:
            print("  !", type(e).__name__, e)


if __name__ == "__main__":
    import sys
    demo() if len(sys.argv) > 1 and sys.argv[1] == "demo" else main()
