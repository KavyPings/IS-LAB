# LAB 8 - ADDITIONAL QUESTION 1
# "Demonstrate how to securely store and transmit data using GnuPG.
#  Also create a digital signature for the data and verify it after transmission."
#
# GnuPG is a command line tool, not a Python library, and it will not be
# installed in an exam machine or a virtual environment. So this file does
# two things:
#
#   PART A  the exact gpg commands, as comments, in the right order - put
#           these in the write-up
#   PART B  the same OpenPGP workflow implemented with pycryptodome, so there
#           is something to RUN and show outputs for
#
# The OpenPGP flow is a HYBRID: a random session key encrypts the data with a
# symmetric cipher, and the session key is encrypted to the recipient's public
# key. Signing is separate and independent of encryption.
#
# ------------------------------------------------------------------------
# PART A : the gpg commands (write these in the answer sheet)
# ------------------------------------------------------------------------
#   gpg --full-generate-key                      create a key pair
#   gpg --list-keys                              see key ids and fingerprints
#   gpg --armor --export alice@x.com > alice.asc  export the public key
#   gpg --import bob.asc                         import the other party's key
#
#   # confidentiality: encrypt to Bob, only Bob can read it
#   gpg --encrypt --recipient bob@x.com --output secret.gpg message.txt
#   gpg --decrypt --output message.txt secret.gpg
#
#   # authenticity: a DETACHED signature, so the file stays as it is
#   gpg --detach-sign --armor --output message.sig message.txt
#   gpg --verify message.sig message.txt
#
#   # both at once, which is what "securely store and transmit" means
#   gpg --sign --encrypt --recipient bob@x.com --output sealed.gpg message.txt
#   gpg --decrypt sealed.gpg            # decrypts AND reports the signature
#
#   # symmetric only, when there is no key pair
#   gpg --symmetric --cipher-algo AES256 message.txt
#
#   What to say about each step:
#     --encrypt            gives confidentiality
#     --detach-sign        gives integrity, authenticity, non-repudiation
#     --armor              ASCII output so it survives email
#     the order            SIGN then ENCRYPT, so an eavesdropper cannot even
#                          see who signed it
# ------------------------------------------------------------------------

import hashlib
import json
import os
import shutil
import sys

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15

KEY_DIR = "pgp_keys"
SEALED = "sealed.json"


# ---------- key management, the gpg --full-generate-key part ----------

def make_keys(name):
    os.makedirs(KEY_DIR, exist_ok=True)
    private_path = os.path.join(KEY_DIR, name + "_private.pem")
    public_path = os.path.join(KEY_DIR, name + "_public.pem")
    if not os.path.exists(private_path):
        key = RSA.generate(2048)
        open(private_path, "wb").write(key.export_key())
        open(public_path, "wb").write(key.publickey().export_key())
    return (RSA.import_key(open(private_path, "rb").read()),
            RSA.import_key(open(public_path, "rb").read()))


def fingerprint(public_key):
    # gpg --list-keys shows this; it is a hash of the key material
    raw = public_key.export_key(format="DER")
    digest = hashlib.sha256(raw).hexdigest().upper()
    return " ".join(digest[i:i + 4] for i in range(0, 40, 4))


# ---------- sign then encrypt : gpg --sign --encrypt ----------

def seal(message, sender_private, recipient_public):
    data = message.encode()

    # 1 sign the plaintext with the SENDER private key (detached signature)
    digest = SHA256.new(data)
    signature = pkcs1_15.new(sender_private).sign(digest)

    # 2 a fresh random session key, used once
    session_key = get_random_bytes(32)

    # 3 symmetric encryption of the message AND the signature together,
    #   so an eavesdropper cannot even see who signed it
    payload = json.dumps({"message": message, "signature": signature.hex()}).encode()
    cipher = AES.new(session_key, AES.MODE_GCM)
    body, tag = cipher.encrypt_and_digest(payload)

    # 4 the session key is encrypted to the RECIPIENT public key
    wrapped = PKCS1_OAEP.new(recipient_public).encrypt(session_key)

    return {"wrapped_key": wrapped.hex(), "nonce": cipher.nonce.hex(),
            "tag": tag.hex(), "body": body.hex(),
            "sha256": hashlib.sha256(data).hexdigest()}


def unseal(envelope, recipient_private, sender_public):
    # 1 recover the session key with the RECIPIENT private key
    session_key = PKCS1_OAEP.new(recipient_private).decrypt(
        bytes.fromhex(envelope["wrapped_key"]))

    # 2 decrypt and check the AES-GCM tag (integrity of the transport)
    cipher = AES.new(session_key, AES.MODE_GCM, nonce=bytes.fromhex(envelope["nonce"]))
    payload = cipher.decrypt_and_verify(bytes.fromhex(envelope["body"]),
                                        bytes.fromhex(envelope["tag"]))
    inner = json.loads(payload.decode())
    message = inner["message"]

    # 3 verify the signature with the SENDER public key
    digest = SHA256.new(message.encode())
    try:
        pkcs1_15.new(sender_public).verify(digest, bytes.fromhex(inner["signature"]))
        signature_ok = True
    except (ValueError, TypeError):
        signature_ok = False

    # 4 the stored hash, the gpg --verify equivalent for storage at rest
    hash_ok = hashlib.sha256(message.encode()).hexdigest() == envelope["sha256"]
    return message, signature_ok, hash_ok


alice_private, alice_public = make_keys("alice")
bob_private, bob_public = make_keys("bob")
eve_private, eve_public = make_keys("eve")

print("=" * 72)
print(" OpenPGP style secure storage and transmission")
print("=" * 72)
print("alice fingerprint:", fingerprint(alice_public))
print("bob   fingerprint:", fingerprint(bob_public))
print()

message = "Transfer 250000 to account 4471 on 2025-11-03. - Alice"

print("--- Alice seals the message for Bob (sign, then encrypt) ---")
envelope = seal(message, alice_private, bob_public)
json.dump(envelope, open(SEALED, "w"), indent=2)
print("stored in", SEALED, "- this is what travels over the network")
print("  wrapped session key:", envelope["wrapped_key"][:48] + "...")
print("  AES-GCM body       :", envelope["body"][:48] + "...")
print("  GCM tag            :", envelope["tag"])
print("  SHA-256 of message :", envelope["sha256"][:32] + "...")
print()

print("--- Bob opens it ---")
text, signature_ok, hash_ok = unseal(envelope, bob_private, alice_public)
print("  decrypted  :", text)
print("  signature  :", "VALID (Alice signed it, and cannot deny it)"
      if signature_ok else "INVALID")
print("  hash check :", "matches" if hash_ok else "DOES NOT MATCH")
print()

print("--- Eve intercepts the file ---")
try:
    unseal(envelope, eve_private, alice_public)
    print("  Eve read it - something is wrong")
except ValueError as exc:
    print("  Eve cannot unwrap the session key:", type(exc).__name__)
print()

print("--- somebody edits the stored file ---")
tampered = dict(envelope)
raw = bytearray(bytes.fromhex(tampered["body"]))
raw[5] ^= 0x01
tampered["body"] = bytes(raw).hex()
try:
    unseal(tampered, bob_private, alice_public)
    print("  tampering went unnoticed - something is wrong")
except ValueError:
    print("  AES-GCM tag check fails -> tampering detected before decryption")
print()

print("--- the wrong signer ---")
forged = seal(message, eve_private, bob_public)
text, signature_ok, hash_ok = unseal(forged, bob_private, alice_public)
print("  Eve signed, Bob verified against Alice's key -> signature valid:",
      signature_ok)
print()

print("--- which property comes from which step ---")
print("  AES-256-GCM session key   confidentiality + transport integrity")
print("  RSA-OAEP key wrapping     only the named recipient can open it")
print("  RSA PKCS#1 signature      authenticity and non-repudiation")
print("  SHA-256 stored digest     integrity of the record at rest")
print()
# keep the folder tidy; pass --keep to leave the key files behind
if "--keep" not in sys.argv:
    if os.path.exists(SEALED):
        os.remove(SEALED)
    shutil.rmtree(KEY_DIR, ignore_errors=True)
