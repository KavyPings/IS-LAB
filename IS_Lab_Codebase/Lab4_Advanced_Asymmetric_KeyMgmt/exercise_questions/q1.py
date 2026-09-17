"""
LAB 4 - EXERCISE 1 : SecureCorp

Enterprise with three subsystems - Finance (A), HR (B), Supply Chain (C) -
that must exchange signed, encrypted documents.

REQUIREMENTS FROM THE QUESTION AND HOW EACH IS MET
  1. Secure communication using RSA + Diffie-Hellman
       -> DH establishes a per-pair session key (AES-256)
       -> RSA signs every document so the receiver knows who sent it
       -> RSA also encrypts the session key when a subsystem is offline
  2. Key management: generate, distribute, revoke
       -> KeyManager class below
  3. Scalability: new subsystems can join at any time
       -> add_subsystem() - nothing else needs changing

RUN: python q1.py        (menu driven)
"""

import os
import json
import base64
import random
import hashlib
from datetime import datetime

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# Standard 2048-bit Diffie-Hellman group (RFC 3526 group 14)
DH_P = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
           "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
           "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
           "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
           "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
           "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
           "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
           "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
           "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
           "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
           "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
DH_G = 2


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ===========================================================================
# SUBSYSTEM : one business unit (Finance, HR, Supply Chain, ...)
# ===========================================================================
class Subsystem:

    def __init__(self, name, rsa_bits=2048):
        self.name = name
        self.rsa = RSA.generate(rsa_bits)          # long-term identity key
        self.dh_private = random.randrange(2, DH_P - 2)
        self.dh_public = pow(DH_G, self.dh_private, DH_P)
        self.revoked = False
        self.sessions = {}                         # peer name -> AES key

    # --- Diffie-Hellman ---------------------------------------------------
    def start_session(self, peer):
        """Both sides compute the same AES key from each other's DH public."""
        shared = pow(peer.dh_public, self.dh_private, DH_P)
        raw = shared.to_bytes((shared.bit_length() + 7) // 8, "big")
        key = hashlib.sha256(raw).digest()
        self.sessions[peer.name] = key
        return key

    # --- send / receive ---------------------------------------------------
    def send(self, peer, document):
        """AES-encrypt with the DH session key, and RSA-SIGN the document."""
        if self.revoked or peer.revoked:
            raise PermissionError("a revoked subsystem cannot communicate")
        key = self.sessions.get(peer.name) or self.start_session(peer)
        c = AES.new(key, AES.MODE_GCM)
        ct, tag = c.encrypt_and_digest(document.encode())
        signature = pkcs1_15.new(self.rsa).sign(SHA256.new(document.encode()))
        return {"from": self.name, "nonce": c.nonce, "tag": tag,
                "ct": ct, "sig": signature, "ts": now()}

    def receive(self, peer, packet):
        """Decrypt with the session key, then verify the sender's signature."""
        key = self.sessions.get(peer.name) or self.start_session(peer)
        doc = AES.new(key, AES.MODE_GCM,
                      nonce=packet["nonce"]).decrypt_and_verify(packet["ct"],
                                                                packet["tag"])
        ok = True
        try:
            pkcs1_15.new(peer.rsa.publickey()).verify(SHA256.new(doc),
                                                      packet["sig"])
        except (ValueError, TypeError):
            ok = False
        return doc.decode(), ok

    # --- offline delivery: RSA-encrypt the session key ---------------------
    def send_offline(self, peer, document):
        """When no DH handshake is possible, wrap a random AES key in RSA."""
        session = get_random_bytes(32)
        c = AES.new(session, AES.MODE_GCM)
        ct, tag = c.encrypt_and_digest(document.encode())
        enc_key = PKCS1_OAEP.new(peer.rsa.publickey()).encrypt(session)
        sig = pkcs1_15.new(self.rsa).sign(SHA256.new(document.encode()))
        return {"from": self.name, "enc_key": enc_key, "nonce": c.nonce,
                "tag": tag, "ct": ct, "sig": sig, "ts": now()}

    def receive_offline(self, peer, packet):
        session = PKCS1_OAEP.new(self.rsa).decrypt(packet["enc_key"])
        doc = AES.new(session, AES.MODE_GCM,
                      nonce=packet["nonce"]).decrypt_and_verify(packet["ct"],
                                                                packet["tag"])
        try:
            pkcs1_15.new(peer.rsa.publickey()).verify(SHA256.new(doc), packet["sig"])
            ok = True
        except (ValueError, TypeError):
            ok = False
        return doc.decode(), ok


# ===========================================================================
# KEY MANAGER : central registry - generation, distribution, revocation
# ===========================================================================
class KeyManager:

    def __init__(self):
        self.systems = {}
        self.log = []

    def _record(self, action, who, extra=""):
        line = f"{now()} | {action:<14} | {who:<16} | {extra}"
        self.log.append(line)
        return line

    def add_subsystem(self, name, bits=2048):
        """SCALABILITY: adding a new unit is a single call."""
        self.systems[name] = Subsystem(name, bits)
        self._record("KEY_GENERATED", name, f"{bits}-bit RSA + DH key pair")
        return self.systems[name]

    def public_key(self, name):
        """DISTRIBUTION: hand out the public key (never the private one)."""
        s = self.systems[name]
        if s.revoked:
            raise PermissionError(f"{name} is revoked")
        self._record("KEY_DISTRIBUTED", name)
        return s.rsa.publickey()

    def _forget_sessions_with(self, name):
        """Every peer must drop its cached session key for this subsystem,
        otherwise it would keep using a key derived from the OLD DH value."""
        for s in self.systems.values():
            s.sessions.pop(name, None)

    def revoke(self, name, reason="unspecified"):
        self.systems[name].revoked = True
        self.systems[name].sessions.clear()        # tear down its own sessions
        self._forget_sessions_with(name)           # and everyone else's
        self._record("KEY_REVOKED", name, reason)

    def renew(self, name):
        """Rotation: throw away the old pair and issue a fresh one."""
        bits = self.systems[name].rsa.size_in_bits()
        self.systems[name] = Subsystem(name, bits)
        self._forget_sessions_with(name)           # old session keys are dead
        self._record("KEY_RENEWED", name, f"new {bits}-bit pair")

    def status(self):
        print(f"  {'subsystem':<18}{'RSA bits':<10}{'revoked':<9}{'sessions'}")
        for n, s in self.systems.items():
            print(f"  {n:<18}{s.rsa.size_in_bits():<10}{str(s.revoked):<9}"
                  f"{list(s.sessions) or '-'}")

    def audit(self):
        for line in self.log:
            print("  " + line)


# ===========================================================================
# MENU
# ===========================================================================
def main():
    km = KeyManager()
    for n in ("FinanceSystem", "HRSystem", "SupplyChain"):
        km.add_subsystem(n)
    print("=== SecureCorp secure communication system ===")
    print("subsystems created: Finance, HR, SupplyChain")

    while True:
        print("\n1 status  2 send document  3 add subsystem  4 revoke"
              "  5 renew  6 audit log  7 run full demo  0 exit")
        c = input("choice> ").strip()
        if c == "1":
            km.status()
        elif c == "2":
            a = input("  from: ").strip()
            b = input("  to  : ").strip()
            if a not in km.systems or b not in km.systems:
                print("  ! unknown subsystem"); continue
            doc = input("  document: ")
            try:
                pkt = km.systems[a].send(km.systems[b], doc)
                text, ok = km.systems[b].receive(km.systems[a], pkt)
                print(f"  ciphertext : {pkt['ct'].hex()[:56]}...")
                print(f"  received   : {text}")
                print(f"  signature  : {'VALID' if ok else 'INVALID'}")
            except PermissionError as e:
                print("  !", e)
        elif c == "3":
            km.add_subsystem(input("  new subsystem name: ").strip())
            print("  added - no other code changed (scalability)")
        elif c == "4":
            km.revoke(input("  subsystem: ").strip(), input("  reason: "))
        elif c == "5":
            km.renew(input("  subsystem: ").strip())
        elif c == "6":
            km.audit()
        elif c == "7":
            demo(km)
        elif c == "0":
            return


def demo(km=None):
    km = km or KeyManager()
    if not km.systems:
        for n in ("FinanceSystem", "HRSystem", "SupplyChain"):
            km.add_subsystem(n)
    fin, hr, sc = (km.systems[n] for n in ("FinanceSystem", "HRSystem", "SupplyChain"))

    print("\n--- 1. DH session + signed document ---")
    pkt = fin.send(hr, "Q3 financial report: revenue 14.2 Cr")
    text, ok = hr.receive(fin, pkt)
    print("  HR received :", text)
    print("  signature   :", "VALID" if ok else "INVALID")

    print("\n--- 2. tampered document is detected ---")
    pkt2 = fin.send(sc, "Purchase order PO-9931 approved")
    bad = dict(pkt2, sig=pkt2["sig"][:-1] + bytes([pkt2["sig"][-1] ^ 1]))
    text, ok = sc.receive(fin, bad)
    print("  SupplyChain received:", text)
    print("  signature   :", "VALID" if ok else "INVALID (tampered)")

    print("\n--- 3. offline delivery via RSA-wrapped key ---")
    pkt3 = hr.send_offline(fin, "Employee contract EMP-2201")
    text, ok = fin.receive_offline(hr, pkt3)
    print("  Finance received:", text, "| signature:", "VALID" if ok else "INVALID")

    print("\n--- 4. scalability: add a new subsystem ---")
    legal = km.add_subsystem("LegalSystem")
    pkt4 = legal.send(fin, "NDA draft v2")
    print("  Legal -> Finance:", fin.receive(legal, pkt4))

    print("\n--- 5. revocation ---")
    km.revoke("HRSystem", "suspected compromise")
    try:
        fin.send(hr, "payroll data")
    except PermissionError as e:
        print("  blocked:", e)

    print("\n--- 6. renewal restores service with NEW keys ---")
    km.renew("HRSystem")
    hr2 = km.systems["HRSystem"]
    print("  Finance -> HR:", hr2.receive(fin, fin.send(hr2, "payroll data")))

    print("\n--- audit log ---")
    km.audit()


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "demo":
        demo()
    else:
        main()
