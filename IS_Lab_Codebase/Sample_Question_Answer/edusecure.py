"""
=============================================================================
 SAMPLE QUESTION ANSWER : "EduSecure" - secure education data management
 (ICT 3141 Information Security Lab - Mid-Term sample paper)
=============================================================================

WHAT THE QUESTION ASKS FOR
  DES symmetric encryption ....... store academic records confidentially
  RSA digital signatures ......... authenticate the user who uploaded
  SHA-256 hashing ................ verify the record was not modified
  Role based access control ...... Student / Faculty / HoD
  Menu driven program ............ interactive
  File or database storage ....... records survive between runs

FLOW (this is the part worth the marks - learn this order)
  STUDENT   : record ---DES encrypt---> ciphertext
                       ---SHA256------> hash of the CIPHERTEXT
                       ---RSA sign----> signature over that hash
                       store {ciphertext, hash, signature, timestamp}
  FACULTY   : DES decrypt -> plaintext
              recompute SHA-256 of ciphertext -> compare with stored hash
              RSA verify signature with the student's public key
  HOD       : sees hashes + timestamps only (never the plaintext)
              can still verify signatures

HOW TO REUSE THIS FILE
  It is deliberately split into small labelled sections. For a different
  question, swap:
      * des_encrypt/des_decrypt  -> aes_encrypt/aes_decrypt   (Lab 2)
      * rsa_sign/rsa_verify      -> ElGamal / ECDSA signing    (Lab 6)
      * ROLES dict               -> whatever roles are asked for
  Everything else (menu, storage, hashing, login) stays the same.

RUN:  python edusecure.py
=============================================================================
"""

import os
import json
import base64
import hashlib
from datetime import datetime

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------
DB_FILE = "edusecure_db.json"          # our "database"
KEY_DIR = "edusecure_keys"             # RSA key files live here
SHARED_DES_KEY = b"EduSec01"           # 8 bytes exactly - DES key size


# ===========================================================================
# SECTION 1 : SMALL HELPERS (conversion + time)
# ===========================================================================

def now():
    """Timestamp string stored with every record."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def b64(data):
    """bytes -> text, so ciphertext can live inside a JSON file."""
    return base64.b64encode(data).decode()


def unb64(text):
    """text -> bytes"""
    return base64.b64decode(text)


# ===========================================================================
# SECTION 2 : DES ENCRYPTION  (confidentiality)
# ===========================================================================

def des_encrypt(plaintext, key=SHARED_DES_KEY):
    """DES-ECB. Block size is 8 bytes, so the data must be padded first."""
    data = plaintext.encode() if isinstance(plaintext, str) else plaintext
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(pad(data, 8))            # pad -> multiple of 8


def des_decrypt(ciphertext, key=SHARED_DES_KEY):
    """Same key, reverse operation, then remove the padding."""
    cipher = DES.new(key, DES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), 8).decode()


# ===========================================================================
# SECTION 3 : SHA-256 HASHING  (integrity)
# ===========================================================================

def sha256_hex(data):
    """Hash of bytes or str -> 64 hex characters."""
    data = data.encode() if isinstance(data, str) else data
    return hashlib.sha256(data).hexdigest()


# ===========================================================================
# SECTION 4 : RSA DIGITAL SIGNATURE  (authenticity / non-repudiation)
# ===========================================================================

def rsa_generate(username, bits=2048):
    """Create an RSA key pair for a user and save it to disk."""
    os.makedirs(KEY_DIR, exist_ok=True)
    key = RSA.generate(bits)
    with open(os.path.join(KEY_DIR, f"{username}_private.pem"), "wb") as f:
        f.write(key.export_key())
    with open(os.path.join(KEY_DIR, f"{username}_public.pem"), "wb") as f:
        f.write(key.publickey().export_key())
    return key


def load_private(username):
    with open(os.path.join(KEY_DIR, f"{username}_private.pem"), "rb") as f:
        return RSA.import_key(f.read())


def load_public(username):
    with open(os.path.join(KEY_DIR, f"{username}_public.pem"), "rb") as f:
        return RSA.import_key(f.read())


def rsa_sign(message, private_key):
    """Sign = RSA private-key operation on the SHA-256 hash of the message."""
    data = message.encode() if isinstance(message, str) else message
    return pkcs1_15.new(private_key).sign(SHA256.new(data))


def rsa_verify(message, signature, public_key):
    """Returns True/False (the library raises, we catch it for a clean menu)."""
    data = message.encode() if isinstance(message, str) else message
    try:
        pkcs1_15.new(public_key).verify(SHA256.new(data), signature)
        return True
    except (ValueError, TypeError):
        return False


# ===========================================================================
# SECTION 5 : STORAGE  (a JSON file acting as the database)
# ===========================================================================

def load_db():
    if os.path.exists(DB_FILE):
        with open(DB_FILE) as f:
            return json.load(f)
    return {"users": {}, "records": [], "verifications": []}


def save_db(db):
    with open(DB_FILE, "w") as f:
        json.dump(db, f, indent=2)


# ===========================================================================
# SECTION 6 : ACCESS CONTROL  (role based)
# ===========================================================================

# Each role is allowed only these actions. This dict IS the access control.
ROLES = {
    "student": {"upload", "view_own"},
    "faculty": {"decrypt", "verify", "hash", "view_all", "view_verifications"},
    "hod":     {"view_hashes", "verify"},
}


def hash_password(password, salt):
    return hashlib.sha256(bytes.fromhex(salt) + password.encode()).hexdigest()


def register(db, username, password, role):
    """Create the account, the salted password hash, and the RSA key pair."""
    if role not in ROLES:
        print("  ! unknown role"); return False
    if username in db["users"]:
        print("  ! user already exists"); return False
    salt = os.urandom(16).hex()
    db["users"][username] = {
        "role": role,
        "salt": salt,
        "pw": hash_password(password, salt),
        "created": now(),
    }
    rsa_generate(username)                        # every user gets RSA keys
    save_db(db)
    print(f"  + registered '{username}' as {role} (RSA key pair created)")
    return True


def login(db, username, password):
    u = db["users"].get(username)
    if not u or hash_password(password, u["salt"]) != u["pw"]:
        return None
    return {"username": username, "role": u["role"]}


def can(session, action):
    """The single permission check used before every operation."""
    return action in ROLES.get(session["role"], set())


def require(session, action):
    if not can(session, action):
        raise PermissionError(
            f"ACCESS DENIED: role '{session['role']}' cannot perform '{action}'")


# ===========================================================================
# SECTION 7 : THE THREE ROLE OPERATIONS
# ===========================================================================

def student_upload(db, session, filename, content):
    """Student: DES-encrypt -> SHA-256 the ciphertext -> RSA-sign that hash."""
    require(session, "upload")

    ciphertext = des_encrypt(content)                       # 1. confidentiality
    digest = sha256_hex(ciphertext)                         # 2. integrity
    signature = rsa_sign(digest, load_private(session["username"]))  # 3. authenticity

    record = {
        "id": len(db["records"]) + 1,
        "owner": session["username"],
        "filename": filename,
        "ciphertext": b64(ciphertext),
        "hash": digest,
        "signature": b64(signature),
        "timestamp": now(),
    }
    db["records"].append(record)
    save_db(db)

    print("\n  Record uploaded")
    print(f"  file       : {filename}")
    print(f"  ciphertext : {ciphertext.hex()[:64]}...")
    print(f"  SHA-256    : {digest}")
    print(f"  signature  : {signature.hex()[:64]}...")
    print(f"  timestamp  : {record['timestamp']}")
    return record


def student_view_own(db, session):
    require(session, "view_own")
    mine = [r for r in db["records"] if r["owner"] == session["username"]]
    if not mine:
        print("  (no records yet)"); return
    for r in mine:
        print(f"\n  #{r['id']} {r['filename']}   [{r['timestamp']}]")
        print(f"     encrypted : {unb64(r['ciphertext']).hex()[:60]}...")
        print(f"     hash      : {r['hash']}")


def faculty_process(db, session, record_id):
    """Faculty: decrypt with the shared DES key, recompute the hash, verify."""
    require(session, "decrypt")
    record = next((r for r in db["records"] if r["id"] == record_id), None)
    if not record:
        print("  ! no such record"); return

    ciphertext = unb64(record["ciphertext"])

    # (a) INTEGRITY first - recompute SHA-256 of the ciphertext and compare.
    #     Checking before decrypting is the correct order: never process data
    #     you have not yet proved is unmodified.
    recomputed = sha256_hex(ciphertext)
    integrity_ok = (recomputed == record["hash"])

    # (b) AUTHENTICITY - verify the student's RSA signature over that hash
    signature_ok = rsa_verify(record["hash"], unb64(record["signature"]),
                              load_public(record["owner"]))

    # (c) DECRYPT with the shared DES key
    try:
        plaintext = des_decrypt(ciphertext)
    except (ValueError, UnicodeDecodeError):
        plaintext = "<could not decrypt - wrong key or corrupted ciphertext>"

    print(f"\n  record     : #{record['id']} {record['filename']} "
          f"(uploaded by {record['owner']} at {record['timestamp']})")
    print(f"  plaintext  : {plaintext}")
    print(f"  stored hash: {record['hash']}")
    print(f"  recomputed : {recomputed}")
    print(f"  INTEGRITY  : {'OK' if integrity_ok else 'FAILED - record modified'}")
    print(f"  SIGNATURE  : {'VALID' if signature_ok else 'INVALID - not authentic'}")

    db["verifications"].append({
        "record_id": record["id"],
        "verified_by": session["username"],
        "integrity": integrity_ok,
        "signature": signature_ok,
        "timestamp": now(),
    })
    save_db(db)


def faculty_view_verifications(db, session):
    require(session, "view_verifications")
    if not db["verifications"]:
        print("  (no verification results yet)"); return
    for v in db["verifications"]:
        print(f"  record #{v['record_id']} by {v['verified_by']} "
              f"| integrity={v['integrity']} signature={v['signature']} "
              f"| {v['timestamp']}")


def hod_view_hashes(db, session):
    """HoD sees ONLY hashes + timestamps - never the plaintext or ciphertext."""
    require(session, "view_hashes")
    if not db["records"]:
        print("  (no records)"); return
    print(f"\n  {'id':<4}{'owner':<12}{'file':<22}{'timestamp':<21}hash")
    for r in db["records"]:
        print(f"  {r['id']:<4}{r['owner']:<12}{r['filename']:<22}"
              f"{r['timestamp']:<21}{r['hash'][:32]}...")


def verify_signature_only(db, session, record_id):
    """Both Faculty and HoD may do this."""
    require(session, "verify")
    record = next((r for r in db["records"] if r["id"] == record_id), None)
    if not record:
        print("  ! no such record"); return
    ok = rsa_verify(record["hash"], unb64(record["signature"]),
                    load_public(record["owner"]))
    print(f"  signature of record #{record_id} by {record['owner']}: "
          f"{'VALID' if ok else 'INVALID'}")


# ===========================================================================
# SECTION 8 : MENU  (the interactive part)
# ===========================================================================

def student_menu(db, session):
    while True:
        print(f"\n--- STUDENT MENU ({session['username']}) ---")
        print("1. Upload a record (DES encrypt + SHA-256 + RSA sign)")
        print("2. View my uploaded records")
        print("0. Logout")
        c = input("choice> ").strip()
        if c == "1":
            fname = input("  file name (e.g. ISL-5CCE-A2.txt): ").strip() or "record.txt"
            if os.path.exists(fname):                  # read a real file if it exists
                content = open(fname).read()
                print(f"  (read {len(content)} characters from {fname})")
            else:
                content = input("  record contents: ")
            student_upload(db, session, fname, content)
        elif c == "2":
            student_view_own(db, session)
        elif c == "0":
            return


def faculty_menu(db, session):
    while True:
        print(f"\n--- FACULTY MENU ({session['username']}) ---")
        print("1. List all records")
        print("2. Decrypt + verify a record")
        print("3. View stored verification results")
        print("0. Logout")
        c = input("choice> ").strip()
        if c == "1":
            for r in db["records"]:
                print(f"  #{r['id']} {r['filename']} by {r['owner']} [{r['timestamp']}]")
        elif c == "2":
            try:
                faculty_process(db, session, int(input("  record id: ")))
            except ValueError:
                print("  ! enter a number")
        elif c == "3":
            faculty_view_verifications(db, session)
        elif c == "0":
            return


def hod_menu(db, session):
    while True:
        print(f"\n--- HoD MENU ({session['username']}) ---")
        print("1. View hashed records with timestamps")
        print("2. Verify a record's signature")
        print("0. Logout")
        c = input("choice> ").strip()
        if c == "1":
            hod_view_hashes(db, session)
        elif c == "2":
            try:
                verify_signature_only(db, session, int(input("  record id: ")))
            except ValueError:
                print("  ! enter a number")
        elif c == "0":
            return


MENUS = {"student": student_menu, "faculty": faculty_menu, "hod": hod_menu}


def main():
    db = load_db()
    print("=" * 62)
    print("EduSecure - Secure Education Data Management System".center(62))
    print("DES encryption | RSA signatures | SHA-256 integrity".center(62))
    print("=" * 62)
    while True:
        print("\n1. Register   2. Login   0. Exit")
        c = input("choice> ").strip()
        if c == "1":
            u = input("  username: ").strip()
            p = input("  password: ").strip()
            r = input("  role (student/faculty/hod): ").strip().lower()
            register(db, u, p, r)
        elif c == "2":
            u = input("  username: ").strip()
            p = input("  password: ").strip()
            session = login(db, u, p)
            if not session:
                print("  ! invalid credentials"); continue
            print(f"  welcome {u} ({session['role']})")
            try:
                MENUS[session["role"]](db, session)
            except PermissionError as e:
                print("  !", e)
        elif c == "0":
            print("bye"); return


# ===========================================================================
# SECTION 9 : NON-INTERACTIVE DEMO  (run:  python edusecure.py demo)
# Useful to show the examiner the whole flow without typing, and to prove
# that tampering is detected.
# ===========================================================================

def demo():
    for f in (DB_FILE,):
        if os.path.exists(f):
            os.remove(f)
    db = load_db()
    register(db, "kavy", "pw1", "student")
    register(db, "prof", "pw2", "faculty")
    register(db, "hod1", "pw3", "hod")

    print("\n--- STUDENT uploads ---")
    st = login(db, "kavy", "pw1")
    student_upload(db, st, "ISL-5CCE-A2.txt", "Sem5 CCE A2 | DBMS 95 | IS 92")

    print("\n--- FACULTY decrypts + verifies ---")
    fa = login(db, "prof", "pw2")
    faculty_process(db, fa, 1)

    print("\n--- HoD sees hashes only ---")
    hd = login(db, "hod1", "pw3")
    hod_view_hashes(db, hd)
    verify_signature_only(db, hd, 1)

    print("\n--- ACCESS CONTROL check: HoD tries to decrypt ---")
    try:
        faculty_process(db, hd, 1)
    except PermissionError as e:
        print("  ", e)

    print("\n--- TAMPER TEST: someone edits the stored ciphertext ---")
    bad = bytearray(unb64(db["records"][0]["ciphertext"]))
    bad[0] ^= 0x01                              # flip one bit
    db["records"][0]["ciphertext"] = b64(bytes(bad))
    save_db(db)
    faculty_process(db, fa, 1)                  # integrity must now FAIL


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "demo":
        demo()
    else:
        main()
