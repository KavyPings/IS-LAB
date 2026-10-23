# LAB 8 - SAMPLE / SCENARIO QUESTION
# "SecureDocs" - an encrypted document archive the server can search but
# cannot read.
#
# THE SHAPE OF THE QUESTION
#   Staff upload documents. The archive server stores only ciphertext and an
#   encrypted index. Staff can search by keyword, by category and by upload
#   time range. A reviewer verifies integrity and signatures. An auditor sees
#   hashes only. Nobody except the uploader and the reviewer sees content.
#
# WHAT IS USED AND WHY
#   AES-256-CBC   document confidentiality
#   HMAC-SHA256   deterministic search tokens  (Lab 8 SSE)
#   SHA-256       integrity of each document
#   RSA PKCS#1    signature: who uploaded it, and they cannot deny it
#   roles         staff / reviewer / auditor
#
# RUN
#   python q1.py          menu
#   python q1.py demo     full run with no typing
#   python q1.py reset    delete the stored files

import hashlib
import hmac
import json
import os
import sys
from datetime import datetime, timedelta

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad

try:
    sys.stdout.reconfigure(errors="replace")
except Exception:
    pass

# ===== SETTINGS =====
system_name = "SecureDocs"
roles = {
    "staff": ["upload", "search", "view_own"],
    "reviewer": ["search", "verify", "read", "tamper_test"],
    "auditor": ["view_hashes", "audit"]
}
# ===== END SETTINGS =====

documents = {}                 # doc id -> envelope
search_index = {}              # token -> [[iv, encrypted doc id]]
user_keys = {}
doc_file = "securedocs.json"
index_file = "securedocs_index.json"
key_file = "securedocs_keys.json"
log_file = "securedocs.log"


def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ---------- encryption ----------

def master_key():
    # in a real system this comes from a KDF over a passphrase
    return hashlib.sha256((system_name + "-master").encode()).digest()


def encrypt_data(key, text):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv, cipher.encrypt(pad(text.encode(), 16))


def decrypt_data(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), 16).decode(errors="replace")


# ---------- hashing and signatures ----------

def hash_data(text):
    return hashlib.sha256(text.encode()).hexdigest()


def get_keys(user):
    if user not in user_keys:
        key = RSA.generate(2048)
        user_keys[user] = {"private": key.export_key().decode(),
                           "public": key.publickey().export_key().decode()}
        log_action(user, "RSA key pair generated")
    return user_keys[user]


def sign_data(digest_hex, user):
    private = RSA.import_key(get_keys(user)["private"])
    return pkcs1_15.new(private).sign(SHA256.new(digest_hex.encode())).hex()


def verify_signature(digest_hex, signature, user):
    public = RSA.import_key(user_keys[user]["public"])
    try:
        pkcs1_15.new(public).verify(SHA256.new(digest_hex.encode()),
                                    bytes.fromhex(signature))
        return True
    except (ValueError, TypeError):
        return False


# ---------- searchable index ----------

def token(label):
    return hmac.new(key, label.lower().encode(), hashlib.sha256).hexdigest()


def index_add(label, doc_id):
    iv, encrypted = encrypt_data(key, doc_id)
    search_index.setdefault(token(label), []).append([iv.hex(), encrypted.hex()])


def index_lookup(label):
    hits = []
    for iv_hex, ct_hex in search_index.get(token(label), []):
        hits.append(decrypt_data(key, bytes.fromhex(iv_hex), bytes.fromhex(ct_hex)))
    return sorted(set(hits))


def minute_bucket(stamp):
    return "time:" + stamp[:16]


def search_keyword(word):
    return index_lookup(word)


def search_category(category):
    return index_lookup("cat:" + str(category))


def search_time_range(start, end):
    t0 = datetime.strptime(start, "%Y-%m-%d %H:%M")
    t1 = datetime.strptime(end, "%Y-%m-%d %H:%M")
    found = []
    while t0 <= t1:
        found += index_lookup(minute_bucket(t0.strftime("%Y-%m-%d %H:%M")))
        t0 += timedelta(minutes=1)
    return sorted(set(found))


# ---------- storage, log, access control ----------

def save_all():
    json.dump(documents, open(doc_file, "w"), indent=2)
    json.dump(search_index, open(index_file, "w"), indent=2)
    json.dump(user_keys, open(key_file, "w"), indent=2)


def load_all():
    global documents, search_index, user_keys
    if os.path.exists(doc_file):
        documents = json.load(open(doc_file))
    if os.path.exists(index_file):
        search_index = json.load(open(index_file))
    if os.path.exists(key_file):
        user_keys = json.load(open(key_file))


def log_action(who, what):
    open(log_file, "a").write("%s | %s | %s\n" % (timestamp(), who, what))


def show_log():
    if not os.path.exists(log_file):
        print("log is empty")
        return
    for line in open(log_file):
        print(line.rstrip())


def allowed(role, action):
    if action not in roles.get(role, []):
        print("ACCESS DENIED:", role, "cannot", action)
        log_action(role, "DENIED " + action)
        return False
    return True


# ---------- the operations ----------

def upload(user, doc_id, category, text):
    if not allowed("staff", "upload"):
        return
    digest = hash_data(text)
    iv, ciphertext = encrypt_data(key, text)
    signature = sign_data(digest, user)
    stamp = timestamp()

    documents[doc_id] = {"user": user, "category": str(category),
                         "iv": iv.hex(), "ciphertext": ciphertext.hex(),
                         "hash": digest, "signature": signature,
                         "timestamp": stamp, "status": "stored"}

    for word in set(text.lower().split()):
        index_add(word, doc_id)
    index_add("cat:" + str(category), doc_id)
    index_add(minute_bucket(stamp), doc_id)
    save_all()
    log_action(user, "upload " + doc_id)

    print("stored", doc_id)
    print("  SHA-256 (hex):", digest)
    print("  AES-256-CBC IV:", iv.hex().upper())
    print("  ciphertext    :", ciphertext.hex().upper()[:64] + "...")
    print("  RSA signature :", signature.upper()[:48] + "...")
    print("  indexed words :", len(set(text.lower().split())), "+ category + time")


def verify(doc_id):
    if not allowed("reviewer", "verify"):
        return False
    if doc_id not in documents:
        print("no such document:", doc_id)
        return False
    row = documents[doc_id]
    try:
        text = decrypt_data(key, bytes.fromhex(row["iv"]), bytes.fromhex(row["ciphertext"]))
    except ValueError:
        text = ""
    hash_ok = hash_data(text) == row["hash"]
    sig_ok = verify_signature(row["hash"], row["signature"], row["user"])
    print("document :", doc_id, "uploaded by", row["user"], "at", row["timestamp"])
    print("content  :", text or "<unreadable>")
    print("SHA-256  :", "matches" if hash_ok else "DOES NOT MATCH")
    print("signature:", "valid" if sig_ok else "INVALID")
    row["status"] = "verified" if (hash_ok and sig_ok) else "FAILED"
    save_all()
    log_action("reviewer", "verify %s -> %s" % (doc_id, row["status"]))
    return hash_ok and sig_ok


def tamper(doc_id):
    if not allowed("reviewer", "tamper_test"):
        return
    row = documents[doc_id]
    raw = bytearray(bytes.fromhex(row["ciphertext"]))
    raw[0] ^= 0x01
    row["ciphertext"] = bytes(raw).hex()
    save_all()
    print("tampered with", doc_id, "- now verify it again")


def view_own(user):
    if not allowed("staff", "view_own"):
        return
    for doc_id, row in documents.items():
        if row["user"] == user:
            print(doc_id, "|", row["category"], "|", row["timestamp"], "|", row["status"])


def show_hashes():
    if not allowed("auditor", "view_hashes"):
        return
    print("%-8s %-10s %-20s %s" % ("DOC", "USER", "TIMESTAMP", "SHA-256"))
    for doc_id, row in documents.items():
        print("%-8s %-10s %-20s %s" % (doc_id, row["user"], row["timestamp"],
                                       row["hash"][:32] + "..."))


# ---------- demonstration and menu ----------

CORPUS = [
    ("D001", "finance", "quarterly revenue report for the finance department"),
    ("D002", "finance", "audit of encrypted financial records and invoices"),
    ("D003", "hr", "employee onboarding policy and salary bands"),
    ("D004", "legal", "vendor contract with an arbitration clause"),
    ("D005", "hr", "annual appraisal process for the hr department"),
]


def demo():
    print("=" * 70)
    print(" " + system_name + " - full demonstration")
    print("=" * 70)
    print("\n--- STAFF upload ---")
    for doc_id, category, text in CORPUS:
        upload("alice" if category == "finance" else "bob", doc_id, category, text)
        print()

    print("--- SEARCH over the encrypted index ---")
    for word in ["encrypted", "department", "salary", "blockchain"]:
        print("  keyword %-12s ->" % word, ", ".join(search_keyword(word)) or "none")
    print("  category finance    ->", ", ".join(search_category("finance")))
    print("  category hr         ->", ", ".join(search_category("hr")))
    now = datetime.now()
    start = (now - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M")
    end = (now + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M")
    print("  time %s .. %s ->" % (start[-5:], end[-5:]),
          ", ".join(search_time_range(start, end)))
    print("  the server matched HMAC tokens only; it never saw a keyword")

    print("\n--- REVIEWER verifies ---")
    verify("D002")

    print("\n--- tamper test ---")
    tamper("D002")
    verify("D002")

    print("\n--- AUDITOR sees integrity data only ---")
    show_hashes()

    print("\n--- ACCESS CONTROL ---")
    allowed("auditor", "read")
    allowed("staff", "verify")

    print("\n--- AUDIT LOG ---")
    show_log()
    print("\n" + "=" * 70)
    print("demonstration finished")


def reset():
    for path in [doc_file, index_file, key_file, log_file]:
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            pass
    print("stored files removed")


def menu():
    while True:
        print("\n" + system_name.upper())
        print("1 Upload | 2 Search | 3 Verify | 4 My documents"
              " | 5 Hashes | 6 Audit log | 7 Tamper test | 8 Exit")
        choice = input("Input Choice: ").strip()
        if choice == "1":
            upload(input("User: ").strip() or "alice",
                   input("Document ID: ").strip() or "D001",
                   input("Category: ").strip() or "finance",
                   input("Content: ").strip() or "sample document text")
        elif choice == "2":
            print("  1 keyword  2 category  3 time range")
            pick = input("  > ").strip()
            if pick == "1":
                print("  ->", ", ".join(search_keyword(input("  word: ").strip())) or "none")
            elif pick == "2":
                print("  ->", ", ".join(search_category(input("  category: ").strip())) or "none")
            else:
                start = input("  from (YYYY-MM-DD HH:MM): ").strip()
                end = input("  to   (YYYY-MM-DD HH:MM): ").strip()
                print("  ->", ", ".join(search_time_range(start, end)) or "none")
        elif choice == "3":
            verify(input("Document ID: ").strip())
        elif choice == "4":
            view_own(input("User: ").strip() or "alice")
        elif choice == "5":
            show_hashes()
        elif choice == "6":
            show_log()
        elif choice == "7":
            tamper(input("Document ID: ").strip())
        elif choice == "8":
            return


if len(sys.argv) > 1 and sys.argv[1] == "reset":
    reset()
    sys.exit(0)

load_all()
key = master_key()

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "demo":
        demo()
    else:
        menu()
