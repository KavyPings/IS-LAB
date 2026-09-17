"""
LAB 3 - SAMPLE / SCENARIO QUESTION (exam style practice)

"SecureMail is an internal e-mail system for a law firm. Every user has an
 RSA key pair. A sender must be able to
    - look up a recipient's public key,
    - encrypt a message so only the recipient can read it,
    - sign it so the recipient knows who sent it.
 The recipient must be able to decrypt and verify. Partners can additionally
 run a Diffie-Hellman key exchange with an external counsel to set up a
 shared channel. Build a menu-driven Python program."

PATTERN: registry of public keys + hybrid encryption + signature + DH.
This is the Lab-3 shape of the mid-term question.
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

DB = "securemail.json"
KEYS = "securemail_keys"

# small DH parameters for the demo (use RFC 3526 group 14 in production)
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


# --- storage ---------------------------------------------------------------
def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def b64(x):
    return base64.b64encode(x).decode()


def unb64(x):
    return base64.b64decode(x)


def load():
    return json.load(open(DB)) if os.path.exists(DB) else {"users": [], "mail": []}


def save(db):
    json.dump(db, open(DB, "w"), indent=2)


# --- key registry ----------------------------------------------------------
def register(db, user):
    os.makedirs(KEYS, exist_ok=True)
    if user in db["users"]:
        print("  already registered"); return
    key = RSA.generate(2048)
    open(os.path.join(KEYS, f"{user}_priv.pem"), "wb").write(key.export_key())
    open(os.path.join(KEYS, f"{user}_pub.pem"), "wb").write(key.publickey().export_key())
    db["users"].append(user)
    save(db)
    print(f"  registered {user} with a 2048-bit RSA key pair")


def priv_of(user):
    return RSA.import_key(open(os.path.join(KEYS, f"{user}_priv.pem"), "rb").read())


def pub_of(user):
    return RSA.import_key(open(os.path.join(KEYS, f"{user}_pub.pem"), "rb").read())


# --- send / read -----------------------------------------------------------
def send_mail(db, sender, recipient, body):
    """Hybrid encryption + RSA signature."""
    if recipient not in db["users"]:
        print("  ! unknown recipient"); return

    # 1. sign the plaintext with the SENDER's private key
    signature = pkcs1_15.new(priv_of(sender)).sign(SHA256.new(body.encode()))

    # 2. encrypt the body with a random AES key
    session = get_random_bytes(32)
    c = AES.new(session, AES.MODE_GCM)
    ct, tag = c.encrypt_and_digest(body.encode())

    # 3. encrypt the AES key with the RECIPIENT's public key
    enc_key = PKCS1_OAEP.new(pub_of(recipient)).encrypt(session)

    db["mail"].append({"id": len(db["mail"]) + 1, "from": sender, "to": recipient,
                       "enc_key": b64(enc_key), "nonce": b64(c.nonce),
                       "tag": b64(tag), "ct": b64(ct), "sig": b64(signature),
                       "timestamp": now()})
    save(db)
    print(f"  sent #{db['mail'][-1]['id']}  ciphertext={ct.hex()[:48]}...")


def read_mail(db, user, mid):
    m = next((x for x in db["mail"] if x["id"] == mid), None)
    if not m:
        print("  ! no such mail"); return
    if m["to"] != user:
        print("  ACCESS DENIED - this mail is not addressed to you"); return

    session = PKCS1_OAEP.new(priv_of(user)).decrypt(unb64(m["enc_key"]))
    body = AES.new(session, AES.MODE_GCM,
                   nonce=unb64(m["nonce"])).decrypt_and_verify(unb64(m["ct"]),
                                                               unb64(m["tag"]))
    try:
        pkcs1_15.new(pub_of(m["from"])).verify(SHA256.new(body), unb64(m["sig"]))
        sig_ok = True
    except (ValueError, TypeError):
        sig_ok = False

    print(f"  from      : {m['from']}   [{m['timestamp']}]")
    print(f"  body      : {body.decode()}")
    print(f"  signature : {'VALID - sender authenticated' if sig_ok else 'INVALID'}")


# --- Diffie-Hellman --------------------------------------------------------
def dh_session():
    a = random.randrange(2, DH_P - 2)
    b = random.randrange(2, DH_P - 2)
    A, B = pow(DH_G, a, DH_P), pow(DH_G, b, DH_P)
    sa, sb = pow(B, a, DH_P), pow(A, b, DH_P)
    print("  partner public  A =", str(A)[:50], "...")
    print("  counsel public  B =", str(B)[:50], "...")
    print("  secrets match     :", sa == sb)
    key = hashlib.sha256(str(sa).encode()).digest()
    print("  derived AES key   :", key.hex())
    c = AES.new(key, AES.MODE_GCM)
    ct, tag = c.encrypt_and_digest(b"case file 2026/114")
    print("  test message      :", ct.hex())
    print("  decrypted         :",
          AES.new(key, AES.MODE_GCM, nonce=c.nonce).decrypt_and_verify(ct, tag).decode())


def main():
    db = load()
    print("=== SecureMail (RSA + AES hybrid + signatures + DH) ===")
    while True:
        print("\n1 register  2 send  3 read  4 list  5 DH exchange  0 exit")
        c = input("choice> ").strip()
        if c == "1":
            register(db, input("  username: ").strip())
        elif c == "2":
            s = input("  from: ").strip()
            r = input("  to  : ").strip()
            if s not in db["users"]:
                print("  ! sender not registered"); continue
            send_mail(db, s, r, input("  body: "))
        elif c == "3":
            u = input("  your username: ").strip()
            try:
                read_mail(db, u, int(input("  mail id: ")))
            except ValueError:
                print("  ! enter a number")
        elif c == "4":
            print("  users:", ", ".join(db["users"]) or "(none)")
            for m in db["mail"]:
                print(f"  #{m['id']} {m['from']} -> {m['to']}  [{m['timestamp']}]")
        elif c == "5":
            dh_session()
        elif c == "0":
            return


if __name__ == "__main__":
    main()
