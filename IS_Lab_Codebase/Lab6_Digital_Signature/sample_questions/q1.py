"""
LAB 6 - SAMPLE / SCENARIO QUESTION (exam style practice)

"SignDesk is an e-signature service for a company's approval workflow.
    - EMPLOYEES upload a document: it is AES-encrypted, its SHA-256 hash
      is signed with their RSA private key, and everything is stored
      with a timestamp,
    - MANAGERS can decrypt a document, verify the employee's signature,
      and counter-sign it,
    - AUDITORS can only see hashes, signatures and timestamps - never the
      document text - and can verify any signature,
    - the system must detect any tampering with stored records.
 Write a menu-driven Python program."

This is the closest Lab-6 practice to the mid-term paper: it uses AES for
confidentiality, SHA-256 for integrity, RSA signatures for authenticity,
and role-based access control - exactly like the EduSecure sample answer.
"""

import os
import json
import base64
import hashlib
from datetime import datetime

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad

DB = "signdesk.json"
KEYS = "signdesk_keys"
SHARED_AES_KEY = bytes.fromhex("00112233445566778899AABBCCDDEEFF"
                               "00112233445566778899AABBCCDDEEFF")   # AES-256

ROLES = {
    "employee": {"upload", "view_own"},
    "manager":  {"decrypt", "verify", "countersign", "view_all"},
    "auditor":  {"view_hashes", "verify"},
}


# --- small helpers ---------------------------------------------------------
def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def b64(x):
    return base64.b64encode(x).decode()


def unb64(x):
    return base64.b64decode(x)


def load():
    return json.load(open(DB)) if os.path.exists(DB) else {"users": {}, "docs": []}


def save(db):
    json.dump(db, open(DB, "w"), indent=2)


# --- crypto primitives -----------------------------------------------------
def aes_encrypt(text):
    return AES.new(SHARED_AES_KEY, AES.MODE_ECB).encrypt(pad(text.encode(), 16))


def aes_decrypt(ct):
    return unpad(AES.new(SHARED_AES_KEY, AES.MODE_ECB).decrypt(ct), 16).decode()


def sha256_hex(data):
    data = data.encode() if isinstance(data, str) else data
    return hashlib.sha256(data).hexdigest()


def keypair(user):
    os.makedirs(KEYS, exist_ok=True)
    k = RSA.generate(2048)
    open(os.path.join(KEYS, f"{user}_priv.pem"), "wb").write(k.export_key())
    open(os.path.join(KEYS, f"{user}_pub.pem"), "wb").write(k.publickey().export_key())


def priv(user):
    return RSA.import_key(open(os.path.join(KEYS, f"{user}_priv.pem"), "rb").read())


def pub(user):
    return RSA.import_key(open(os.path.join(KEYS, f"{user}_pub.pem"), "rb").read())


def sign(message, user):
    return pkcs1_15.new(priv(user)).sign(SHA256.new(message.encode()))


def verify(message, signature, user):
    try:
        pkcs1_15.new(pub(user)).verify(SHA256.new(message.encode()), signature)
        return True
    except (ValueError, TypeError):
        return False


# --- accounts and access control -------------------------------------------
def register(db, user, password, role):
    if role not in ROLES:
        print("  ! unknown role"); return
    salt = os.urandom(16).hex()
    db["users"][user] = {"role": role, "salt": salt,
                         "pw": sha256_hex(bytes.fromhex(salt) + password.encode())}
    keypair(user)
    save(db)
    print(f"  registered {user} as {role} (RSA key pair created)")


def login(db, user, password):
    u = db["users"].get(user)
    if not u:
        return None
    if sha256_hex(bytes.fromhex(u["salt"]) + password.encode()) != u["pw"]:
        return None
    return {"user": user, "role": u["role"]}


def require(session, action):
    if action not in ROLES[session["role"]]:
        raise PermissionError(f"role '{session['role']}' cannot '{action}'")


# --- operations ------------------------------------------------------------
def upload(db, session, title, text):
    require(session, "upload")
    ct = aes_encrypt(text)                       # confidentiality
    digest = sha256_hex(ct)                      # integrity (hash of ciphertext)
    signature = sign(digest, session["user"])    # authenticity
    db["docs"].append({"id": len(db["docs"]) + 1, "title": title,
                       "owner": session["user"], "ct": b64(ct), "hash": digest,
                       "sig": b64(signature), "countersign": None,
                       "countersigner": None, "uploaded": now()})
    save(db)
    d = db["docs"][-1]
    print(f"  uploaded #{d['id']} {title}")
    print(f"    ciphertext : {ct.hex()[:56]}...")
    print(f"    SHA-256    : {digest}")
    print(f"    signature  : {signature.hex()[:56]}...")


def review(db, session, did):
    """Manager: verify integrity + signature, then decrypt."""
    require(session, "decrypt")
    d = next((x for x in db["docs"] if x["id"] == did), None)
    if not d:
        print("  ! no such document"); return
    ct = unb64(d["ct"])
    recomputed = sha256_hex(ct)
    integrity = recomputed == d["hash"]
    authentic = verify(d["hash"], unb64(d["sig"]), d["owner"])
    try:
        text = aes_decrypt(ct)
    except (ValueError, UnicodeDecodeError):
        text = "<cannot decrypt - ciphertext corrupted>"
    print(f"  #{d['id']} {d['title']} by {d['owner']} [{d['uploaded']}]")
    print(f"    stored hash  : {d['hash']}")
    print(f"    recomputed   : {recomputed}")
    print(f"    INTEGRITY    : {'OK' if integrity else 'FAILED - record modified'}")
    print(f"    SIGNATURE    : {'VALID' if authentic else 'INVALID'}")
    print(f"    document     : {text}")


def countersign(db, session, did):
    require(session, "countersign")
    d = next((x for x in db["docs"] if x["id"] == did), None)
    if not d:
        print("  ! no such document"); return
    if not verify(d["hash"], unb64(d["sig"]), d["owner"]):
        print("  ! refusing to counter-sign: the employee signature is invalid")
        return
    d["countersign"] = b64(sign(d["hash"], session["user"]))
    d["countersigner"] = session["user"]
    d["approved"] = now()
    save(db)
    print(f"  #{did} counter-signed by {session['user']} at {d['approved']}")


def view_hashes(db, session):
    """Auditor: hashes, signers and timestamps only - no document text."""
    require(session, "view_hashes")
    if not db["docs"]:
        print("  (no documents)"); return
    print(f"  {'id':<4}{'title':<18}{'owner':<10}{'countersigner':<15}"
          f"{'uploaded':<21}hash")
    for d in db["docs"]:
        print(f"  {d['id']:<4}{d['title']:<18}{d['owner']:<10}"
              f"{str(d['countersigner'] or '-'):<15}{d['uploaded']:<21}"
              f"{d['hash'][:24]}...")


def verify_doc(db, session, did):
    require(session, "verify")
    d = next((x for x in db["docs"] if x["id"] == did), None)
    if not d:
        print("  ! no such document"); return
    print(f"  employee signature   : "
          f"{'VALID' if verify(d['hash'], unb64(d['sig']), d['owner']) else 'INVALID'}")
    if d["countersign"]:
        print(f"  manager counter-sign : "
              f"{'VALID' if verify(d['hash'], unb64(d['countersign']), d['countersigner']) else 'INVALID'}")
    else:
        print("  manager counter-sign : (not counter-signed yet)")


# --- menus -----------------------------------------------------------------
def menu(db, session):
    role = session["role"]
    while True:
        print(f"\n[{session['user']} / {role}]")
        if role == "employee":
            print("1 upload document   2 my documents   0 logout")
        elif role == "manager":
            print("1 list   2 review (decrypt+verify)   3 counter-sign   0 logout")
        else:
            print("1 view hashes   2 verify signatures   0 logout")
        c = input("choice> ").strip()
        try:
            if role == "employee":
                if c == "1":
                    upload(db, session, input("  title: "), input("  content: "))
                elif c == "2":
                    require(session, "view_own")
                    for d in db["docs"]:
                        if d["owner"] == session["user"]:
                            print(f"  #{d['id']} {d['title']} [{d['uploaded']}] "
                                  f"hash {d['hash'][:24]}...")
                elif c == "0":
                    return
            elif role == "manager":
                if c == "1":
                    require(session, "view_all")
                    for d in db["docs"]:
                        print(f"  #{d['id']} {d['title']} by {d['owner']} "
                              f"[{d['uploaded']}]")
                elif c == "2":
                    review(db, session, int(input("  document id: ")))
                elif c == "3":
                    countersign(db, session, int(input("  document id: ")))
                elif c == "0":
                    return
            else:
                if c == "1":
                    view_hashes(db, session)
                elif c == "2":
                    verify_doc(db, session, int(input("  document id: ")))
                elif c == "0":
                    return
        except PermissionError as e:
            print("  ACCESS DENIED:", e)
        except ValueError:
            print("  ! enter a number")


def main():
    db = load()
    print("=" * 60)
    print("SignDesk - e-signature approval workflow".center(60))
    print("AES + SHA-256 + RSA signatures + RBAC".center(60))
    print("=" * 60)
    while True:
        print("\n1 register   2 login   0 exit")
        c = input("choice> ").strip()
        if c == "1":
            register(db, input("  username: ").strip(), input("  password: ").strip(),
                     input("  role (employee/manager/auditor): ").strip().lower())
        elif c == "2":
            s = login(db, input("  username: ").strip(), input("  password: ").strip())
            if s:
                menu(db, s)
            else:
                print("  ! invalid credentials")
        elif c == "0":
            return


def demo():
    for f in (DB,):
        if os.path.exists(f):
            os.remove(f)
    db = load()
    register(db, "emp1", "p1", "employee")
    register(db, "mgr1", "p2", "manager")
    register(db, "aud1", "p3", "auditor")

    print("\n--- employee uploads ---")
    e = login(db, "emp1", "p1")
    upload(db, e, "Leave request", "Leave from 20-09 to 25-09, reason: family")

    print("\n--- manager reviews and counter-signs ---")
    m = login(db, "mgr1", "p2")
    review(db, m, 1)
    countersign(db, m, 1)

    print("\n--- auditor sees hashes only ---")
    a = login(db, "aud1", "p3")
    view_hashes(db, a)
    verify_doc(db, a, 1)

    print("\n--- auditor tries to decrypt ---")
    try:
        review(db, a, 1)
    except PermissionError as err:
        print("  ACCESS DENIED:", err)

    print("\n--- tamper test: ciphertext edited in the store ---")
    bad = bytearray(unb64(db["docs"][0]["ct"]))
    bad[0] ^= 0x01
    db["docs"][0]["ct"] = b64(bytes(bad))
    save(db)
    review(db, m, 1)


if __name__ == "__main__":
    import sys
    demo() if len(sys.argv) > 1 and sys.argv[1] == "demo" else main()
