"""
LAB 2 - SAMPLE / SCENARIO QUESTION (exam style practice)

"MediVault is a hospital record system. Doctors upload patient files which
 must be stored encrypted. The hospital uses AES-256 in CBC mode for files
 and DES for small legacy tags. Build a menu-driven program where
    - a doctor can upload (encrypt) a patient record,
    - a doctor can retrieve (decrypt) a record,
    - an auditor can list records with size, algorithm, mode and timestamp
      but can NEVER decrypt,
    - the system stores everything in a file and survives restarts."

WHY THIS SHAPE MATTERS
  This is the Lab-2 version of the mid-term pattern:
      menu + roles + symmetric encryption + stored records + timestamps.
  Swap AES for DES/3DES, or CBC for CTR, and the rest stays identical.
"""

import os
import json
import base64
from datetime import datetime

from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

DB = "medivault.json"

# In a real system these would come from a key management service (Lab 4).
AES_KEY = bytes.fromhex("00112233445566778899AABBCCDDEEFF"
                        "00112233445566778899AABBCCDDEEFF")   # 32 B, AES-256
DES_KEY = b"legacyK1"                                          # 8 B

ROLES = {"doctor": {"upload", "retrieve", "list"},
         "auditor": {"list"}}                                  # cannot decrypt


# --- helpers ---------------------------------------------------------------
def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def b64(x):
    return base64.b64encode(x).decode()


def unb64(x):
    return base64.b64decode(x)


def load():
    return json.load(open(DB)) if os.path.exists(DB) else []


def save(rows):
    json.dump(rows, open(DB, "w"), indent=2)


# --- encryption ------------------------------------------------------------
def encrypt_record(text, algo="AES"):
    """Returns (iv, ciphertext). CBC needs a fresh random IV per record."""
    if algo == "AES":
        iv = get_random_bytes(16)
        ct = AES.new(AES_KEY, AES.MODE_CBC, iv).encrypt(pad(text.encode(), 16))
    else:                                       # legacy DES
        iv = get_random_bytes(8)
        ct = DES.new(DES_KEY, DES.MODE_CBC, iv).encrypt(pad(text.encode(), 8))
    return iv, ct


def decrypt_record(iv, ct, algo="AES"):
    if algo == "AES":
        return unpad(AES.new(AES_KEY, AES.MODE_CBC, iv).decrypt(ct), 16).decode()
    return unpad(DES.new(DES_KEY, DES.MODE_CBC, iv).decrypt(ct), 8).decode()


# --- operations ------------------------------------------------------------
def upload(role, patient, text, algo):
    if "upload" not in ROLES[role]:
        print("  ACCESS DENIED"); return
    iv, ct = encrypt_record(text, algo)
    rows = load()
    rows.append({"id": len(rows) + 1, "patient": patient, "algo": algo,
                 "mode": "CBC", "iv": b64(iv), "ct": b64(ct),
                 "size": len(text), "timestamp": now()})
    save(rows)
    print(f"  stored record #{rows[-1]['id']}  ciphertext={ct.hex()[:48]}...")


def retrieve(role, rid):
    if "retrieve" not in ROLES[role]:
        print("  ACCESS DENIED - auditors may not decrypt records"); return
    row = next((r for r in load() if r["id"] == rid), None)
    if not row:
        print("  ! no such record"); return
    print("  patient  :", row["patient"])
    print("  algorithm:", row["algo"], row["mode"], "|", row["timestamp"])
    print("  record   :", decrypt_record(unb64(row["iv"]), unb64(row["ct"]),
                                         row["algo"]))


def list_records(role):
    if "list" not in ROLES[role]:
        print("  ACCESS DENIED"); return
    rows = load()
    if not rows:
        print("  (empty)"); return
    print(f"  {'id':<4}{'patient':<14}{'algo':<6}{'mode':<6}{'bytes':<7}{'timestamp'}")
    for r in rows:
        print(f"  {r['id']:<4}{r['patient']:<14}{r['algo']:<6}{r['mode']:<6}"
              f"{r['size']:<7}{r['timestamp']}")


def main():
    print("=== MediVault (AES-256-CBC / legacy DES-CBC) ===")
    role = input("login as (doctor/auditor)> ").strip().lower()
    if role not in ROLES:
        print("unknown role"); return
    while True:
        print(f"\n[{role}] 1 upload  2 retrieve  3 list  0 exit")
        c = input("choice> ").strip()
        if c == "1":
            p = input("  patient name: ")
            t = input("  record text : ")
            a = input("  algorithm (AES/DES): ").strip().upper() or "AES"
            upload(role, p, t, a if a in ("AES", "DES") else "AES")
        elif c == "2":
            try:
                retrieve(role, int(input("  record id: ")))
            except ValueError:
                print("  ! enter a number")
        elif c == "3":
            list_records(role)
        elif c == "0":
            return


if __name__ == "__main__":
    main()
