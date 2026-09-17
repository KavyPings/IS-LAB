"""
LAB 6 - ADDITIONAL 1
"Demonstrate the CIA triad using RSA encryption and digital signature
 along with SHA hashing."

THE CIA TRIAD AND WHICH TOOL PROVIDES EACH
  CONFIDENTIALITY - RSA encryption (+ AES for bulk data)
                    only the holder of the private key can read the message
  INTEGRITY       - SHA-256 hashing
                    any change to the data changes the digest
  AVAILABILITY    - not a cryptographic primitive; shown here as key backup
                    plus a redundant copy of the message store, which is what
                    keeps the data reachable when one copy fails

  (+ AUTHENTICITY / NON-REPUDIATION - RSA digital signature)

The full secure-send routine below is the reusable core of almost every
scenario question.
"""

import os
import json
import base64
import hashlib
import shutil
from datetime import datetime

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

PRIMARY = "cia_store_primary"
BACKUP = "cia_store_backup"


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ===========================================================================
# THE SECURE SEND / RECEIVE PAIR
# ===========================================================================
def secure_send(message, sender_private, receiver_public):
    """Produces one packet containing all three CIA properties."""
    data = message.encode()

    # INTEGRITY - digest of the plaintext
    digest = hashlib.sha256(data).hexdigest()

    # AUTHENTICITY - sign the digest with the SENDER's private key
    signature = pkcs1_15.new(sender_private).sign(SHA256.new(data))

    # CONFIDENTIALITY - AES for the data, RSA for the AES key
    session = get_random_bytes(32)
    c = AES.new(session, AES.MODE_GCM)
    ct, tag = c.encrypt_and_digest(data)
    enc_key = PKCS1_OAEP.new(receiver_public).encrypt(session)

    return {"enc_key": enc_key, "nonce": c.nonce, "tag": tag, "ct": ct,
            "sha256": digest, "signature": signature, "sent": now()}


def secure_receive(pkt, receiver_private, sender_public):
    """Returns (message, confidentiality_ok, integrity_ok, authenticity_ok)."""
    try:
        session = PKCS1_OAEP.new(receiver_private).decrypt(pkt["enc_key"])
        data = AES.new(session, AES.MODE_GCM,
                       nonce=pkt["nonce"]).decrypt_and_verify(pkt["ct"], pkt["tag"])
        conf_ok = True
    except ValueError:
        return None, False, False, False

    integ_ok = hashlib.sha256(data).hexdigest() == pkt["sha256"]
    try:
        pkcs1_15.new(sender_public).verify(SHA256.new(data), pkt["signature"])
        auth_ok = True
    except (ValueError, TypeError):
        auth_ok = False
    return data.decode(), conf_ok, integ_ok, auth_ok


# ===========================================================================
# AVAILABILITY - redundant storage so the data survives a failure
# ===========================================================================
def store(pkt, name):
    """Write the packet to a primary store AND a backup store."""
    blob = json.dumps({k: base64.b64encode(v).decode() if isinstance(v, bytes) else v
                       for k, v in pkt.items()}, indent=2)
    for d in (PRIMARY, BACKUP):
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, f"{name}.json"), "w") as f:
            f.write(blob)


def retrieve(name):
    """Read from the primary; fall back to the backup if it is missing."""
    for d in (PRIMARY, BACKUP):
        path = os.path.join(d, f"{name}.json")
        if os.path.exists(path):
            raw = json.load(open(path))
            print(f"    served from {d}")
            return {k: base64.b64decode(v) if k in
                    ("enc_key", "nonce", "tag", "ct", "signature") else v
                    for k, v in raw.items()}
    raise FileNotFoundError("packet lost from both stores")


if __name__ == "__main__":
    shutil.rmtree(PRIMARY, ignore_errors=True)
    shutil.rmtree(BACKUP, ignore_errors=True)

    alice = RSA.generate(2048)          # sender
    bob = RSA.generate(2048)            # receiver
    eve = RSA.generate(2048)            # attacker
    MESSAGE = "Transfer 250000 INR to account 9912-4471 on 2026-09-20"

    print("=" * 68)
    print("CIA TRIAD DEMONSTRATION")
    print("=" * 68)
    print("message:", MESSAGE)

    pkt = secure_send(MESSAGE, alice, bob.publickey())
    store(pkt, "txn001")
    print("\npacket contents")
    print("  encrypted AES key :", pkt["enc_key"].hex()[:56], "...")
    print("  AES ciphertext    :", pkt["ct"].hex()[:56], "...")
    print("  SHA-256 digest    :", pkt["sha256"])
    print("  RSA signature     :", pkt["signature"].hex()[:56], "...")

    print("\n--- 1. CONFIDENTIALITY ---")
    msg, c_ok, i_ok, a_ok = secure_receive(pkt, bob, alice.publickey())
    print("  Bob (correct private key) reads:", msg)
    out = secure_receive(pkt, eve, alice.publickey())
    print("  Eve (wrong private key) reads  :", out[0],
          "-> confidentiality holds")

    print("\n--- 2. INTEGRITY (SHA-256) ---")
    print(f"  stored digest    : {pkt['sha256']}")
    print(f"  recomputed       : {hashlib.sha256(msg.encode()).hexdigest()}")
    print(f"  integrity ok     : {i_ok}")
    bad = dict(pkt, sha256="0" * 64)          # someone edits the stored digest
    print("  after digest is altered:", secure_receive(bad, bob, alice.publickey())[2])

    print("\n--- 3. AUTHENTICITY / NON-REPUDIATION (RSA signature) ---")
    print("  signature valid under Alice's key:", a_ok)
    print("  signature valid under Eve's key  :",
          secure_receive(pkt, bob, eve.publickey())[3], "-> only Alice could sign")

    forged = secure_send(MESSAGE, eve, bob.publickey())   # Eve impersonates Alice
    print("  Eve signs the same text, checked against Alice's key:",
          secure_receive(forged, bob, alice.publickey())[3], "-> forgery detected")

    print("\n--- 4. AVAILABILITY (redundant storage) ---")
    print("  reading normally:")
    p = retrieve("txn001")
    print("  simulating loss of the primary store ...")
    shutil.rmtree(PRIMARY)
    p = retrieve("txn001")
    print("  recovered message:",
          secure_receive(p, bob, alice.publickey())[0])

    print("""
=== SUMMARY TABLE ===
  property         mechanism used here                  verified by
  ---------------------------------------------------------------------------
  Confidentiality  AES-256-GCM + RSA-OAEP key wrap      only Bob could decrypt
  Integrity        SHA-256 digest (+ GCM auth tag)      digest comparison
  Authenticity     RSA PKCS#1 v1.5 signature            verify with Alice's key
  Non-repudiation  same signature                       only Alice holds the key
  Availability     duplicate store + key backup         served from the backup
""")
