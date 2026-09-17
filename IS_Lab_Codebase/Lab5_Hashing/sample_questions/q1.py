"""
LAB 5 - SAMPLE / SCENARIO QUESTION (exam style practice)

"FileGuard is a document integrity service for an audit department.
    - a user registers a document: the system stores its SHA-256 digest,
      a keyed HMAC and a timestamp (but NOT the document itself),
    - a user can later verify a document against the stored digest,
    - the system detects any modification and reports which check failed,
    - an admin can view the full integrity register,
    - the service must also compare MD5/SHA-1/SHA-256 for the audit report.
 Write a menu-driven Python program."

PATTERN: hashing + HMAC + stored register with timestamps + verification.
"""

import os
import json
import hmac
import hashlib
import time
from datetime import datetime

DB = "fileguard.json"
HMAC_KEY = b"audit-department-secret-key"      # would come from a KMS

ROLES = {"user": {"register", "verify"}, "admin": {"register", "verify", "view", "compare"}}


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def load():
    return json.load(open(DB)) if os.path.exists(DB) else []


def save(rows):
    json.dump(rows, open(DB, "w"), indent=2)


# --- the three integrity primitives ----------------------------------------
def sha256_of(text):
    """Plain digest - proves the content did not change."""
    return hashlib.sha256(text.encode()).hexdigest()


def hmac_of(text):
    """Keyed digest - proves it did not change AND that we produced it.
    Without the key nobody can forge a valid HMAC."""
    return hmac.new(HMAC_KEY, text.encode(), hashlib.sha256).hexdigest()


def digests_of(text):
    """All three algorithms, for the comparison report."""
    return {a: hashlib.new(a, text.encode()).hexdigest()
            for a in ("md5", "sha1", "sha256")}


# --- operations ------------------------------------------------------------
def register(role, name, content):
    if "register" not in ROLES[role]:
        print("  ACCESS DENIED"); return
    rows = load()
    rows.append({"id": len(rows) + 1, "name": name, "size": len(content),
                 "sha256": sha256_of(content), "hmac": hmac_of(content),
                 "registered": now()})
    save(rows)
    r = rows[-1]
    print(f"  registered #{r['id']} {name}")
    print(f"    SHA-256 : {r['sha256']}")
    print(f"    HMAC    : {r['hmac']}")
    print(f"    time    : {r['registered']}")


def verify(role, doc_id, content):
    if "verify" not in ROLES[role]:
        print("  ACCESS DENIED"); return
    row = next((r for r in load() if r["id"] == doc_id), None)
    if not row:
        print("  ! no such document"); return

    new_sha = sha256_of(content)
    new_mac = hmac_of(content)
    sha_ok = hmac.compare_digest(new_sha, row["sha256"])   # timing-safe compare
    mac_ok = hmac.compare_digest(new_mac, row["hmac"])

    print(f"  document  : #{row['id']} {row['name']} "
          f"(registered {row['registered']})")
    print(f"  stored    : {row['sha256']}")
    print(f"  computed  : {new_sha}")
    print(f"  SHA-256   : {'MATCH' if sha_ok else 'MISMATCH'}")
    print(f"  HMAC      : {'MATCH' if mac_ok else 'MISMATCH'}")
    if sha_ok and mac_ok:
        print("  VERDICT   : document is INTACT")
    else:
        print("  VERDICT   : document has been MODIFIED")
        print(f"  (size then {row['size']} bytes, now {len(content)} bytes)")


def view(role):
    if "view" not in ROLES[role]:
        print("  ACCESS DENIED - only admins see the register"); return
    rows = load()
    if not rows:
        print("  (register empty)"); return
    print(f"  {'id':<4}{'name':<20}{'bytes':<7}{'registered':<21}sha-256")
    for r in rows:
        print(f"  {r['id']:<4}{r['name']:<20}{r['size']:<7}{r['registered']:<21}"
              f"{r['sha256'][:32]}...")


def compare(role, sample):
    if "compare" not in ROLES[role]:
        print("  ACCESS DENIED"); return
    print("  digests of the sample text:")
    for a, d in digests_of(sample).items():
        print(f"    {a:<8}({len(d)*4:3d} bits) {d}")
    print("\n  timing over 20000 hashes:")
    for a in ("md5", "sha1", "sha256"):
        t0 = time.perf_counter()
        for _ in range(20000):
            hashlib.new(a, sample.encode()).hexdigest()
        print(f"    {a:<8}{(time.perf_counter()-t0)*1e3:8.2f} ms")
    print("\n  MD5 and SHA-1 have practical collision attacks - use SHA-256.")


def main():
    print("=== FileGuard document integrity service ===")
    role = input("login as (user/admin)> ").strip().lower()
    if role not in ROLES:
        print("unknown role"); return
    while True:
        print(f"\n[{role}] 1 register  2 verify  3 view register"
              "  4 compare algorithms  0 exit")
        c = input("choice> ").strip()
        if c == "1":
            register(role, input("  document name: "), input("  content: "))
        elif c == "2":
            try:
                verify(role, int(input("  document id: ")), input("  content now: "))
            except ValueError:
                print("  ! enter a number")
        elif c == "3":
            view(role)
        elif c == "4":
            compare(role, input("  sample text: ") or "Information Security")
        elif c == "0":
            return


if __name__ == "__main__":
    main()
