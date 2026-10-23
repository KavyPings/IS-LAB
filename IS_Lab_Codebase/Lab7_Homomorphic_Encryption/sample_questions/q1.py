# LAB 7 - SAMPLE / SCENARIO QUESTION
# "SecurePoll" - a privacy preserving survey system.
#
# THE SHAPE OF THE QUESTION
#   Employees answer a satisfaction survey (score 1..5). HR must learn the
#   total and the average, and the count per score, but must never learn any
#   individual answer. Two managers together must authorise the reveal.
#
# WHAT IS USED AND WHY
#   Paillier       the only PHE scheme here that ADDS, so totals work
#   packed counts  encrypting BASE^score lets one number hold five counters
#   SHA-256        integrity of each submitted response
#   Shamir t-of-n  no single manager can decrypt the result
#   roles          employee / hr / manager
#
# RUN
#   python q1.py          menu
#   python q1.py demo     full run with no typing

from Crypto.Util.number import getPrime, GCD
import hashlib
import json
import os
import random
import sys

# ===== SETTINGS =====
BITS = 512
BASE = 10 ** 4                 # must be larger than the number of employees
SCORES = {1: "very unhappy", 2: "unhappy", 3: "neutral", 4: "happy", 5: "very happy"}
THRESHOLD_T = 2
THRESHOLD_N = 3
roles = {
    "employee": ["submit"],
    "hr": ["aggregate", "view_hashes"],
    "manager": ["reveal"]
}
# ===== END SETTINGS =====

responses = {}
data_file = "securepoll.json"


# ---------- Paillier ----------

def keygen():
    if os.path.exists("poll_key.json"):
        return {k: int(v) for k, v in json.load(open("poll_key.json")).items()}
    p = getPrime(BITS // 2)
    q = getPrime(BITS // 2)
    while p == q:
        q = getPrime(BITS // 2)
    n = p * q
    key = {"n": n, "nn": n * n, "secret": (p - 1) * (q - 1)}
    json.dump({k: str(v) for k, v in key.items()}, open("poll_key.json", "w"))
    return key


def encrypt(m):
    n, nn = public_key["n"], public_key["nn"]
    r = random.randrange(1, n)
    while GCD(r, n) != 1:
        r = random.randrange(1, n)
    return ((1 + m * n) * pow(r, n, nn)) % nn


def add(c1, c2):
    return (c1 * c2) % public_key["nn"]


def decrypt(c, secret):
    n, nn = public_key["n"], public_key["nn"]
    u = (pow(c, secret, nn) - 1) // n
    return (u * pow(secret, -1, n)) % n


# ---------- Shamir threshold ----------

def split_secret(secret, t, n, prime):
    coeffs = [secret] + [random.randrange(1, prime) for _ in range(t - 1)]
    return [[i, sum(c * pow(i, j, prime) for j, c in enumerate(coeffs)) % prime]
            for i in range(1, n + 1)]


def combine_shares(shares, prime):
    total = 0
    for xi, yi in shares:
        num, den = 1, 1
        for xj, _ in shares:
            if xi != xj:
                num = (num * -xj) % prime
                den = (den * (xi - xj)) % prime
        total = (total + yi * num * pow(den, -1, prime)) % prime
    return total


# ---------- storage and access control ----------

def save():
    json.dump(responses, open(data_file, "w"), indent=2)


def load():
    global responses
    if os.path.exists(data_file):
        responses = json.load(open(data_file))


def allowed(role, action):
    if action not in roles.get(role, []):
        print("ACCESS DENIED:", role, "cannot", action)
        return False
    return True


# ---------- the three operations ----------

def submit(employee_id, score):
    if not allowed("employee", "submit"):
        return
    score = int(score)
    if score not in SCORES:
        print("score must be 1..5")
        return

    score_ct = encrypt(score)                  # for the total and the average
    packed_ct = encrypt(BASE ** score)         # one counter per score, packed
    digest = hashlib.sha256(("%s:%d" % (employee_id, score)).encode()).hexdigest()

    responses[employee_id] = {"score_ct": str(score_ct),
                              "packed_ct": str(packed_ct),
                              "hash": digest}
    save()
    print("stored response for", employee_id)
    print("  encrypted score :", hex(score_ct)[:30] + "...")
    print("  SHA-256         :", digest[:32] + "...")
    print("  (nobody, including HR, can read the score itself)")


def aggregate():
    if not allowed("hr", "aggregate"):
        return None
    if not responses:
        print("no responses yet")
        return None
    total, packed = encrypt(0), encrypt(0)
    for row in responses.values():
        total = add(total, int(row["score_ct"]))
        packed = add(packed, int(row["packed_ct"]))
    print("combined", len(responses), "encrypted responses")
    print("  encrypted total  :", hex(total)[:30] + "...")
    print("  encrypted counts :", hex(packed)[:30] + "...")
    print("  no individual response was decrypted")
    return total, packed


def reveal(combined):
    if not allowed("manager", "reveal"):
        return
    if combined is None:
        print("aggregate first")
        return
    total, packed = combined

    prime = getPrime(private_secret.bit_length() + 16)
    shares = split_secret(private_secret, THRESHOLD_T, THRESHOLD_N, prime)
    print("%d-of-%d threshold: shares held by %d managers"
          % (THRESHOLD_T, THRESHOLD_N, THRESHOLD_N))

    alone = combine_shares(shares[:1], prime)
    print("  one manager alone reconstructs:", hex(alone)[:22] + "...  (wrong)")

    secret = combine_shares(shares[:THRESHOLD_T], prime)
    print("  %d managers together          : correct = %s"
          % (THRESHOLD_T, secret == private_secret))

    score_total = decrypt(total, secret)
    counts = decrypt(packed, secret)
    count = len(responses)

    print()
    print("total of all scores :", score_total)
    print("average score       : %.2f" % (score_total / count))
    print()
    print("%-6s %-14s %s" % ("score", "meaning", "count"))
    for value, label in sorted(SCORES.items()):
        print("%-6d %-14s %d" % (value, label, (counts // (BASE ** value)) % BASE))


def show_hashes():
    if not allowed("hr", "view_hashes"):
        return
    for eid, row in responses.items():
        print(eid, ":", row["hash"][:40] + "...")


def demo():
    answers = {"E001": 5, "E002": 4, "E003": 4, "E004": 2, "E005": 5, "E006": 3}
    print("=" * 66)
    print(" SecurePoll - full demonstration")
    print("=" * 66)
    print("\n--- EMPLOYEES submit ---")
    for eid, score in answers.items():
        submit(eid, score)
    print("\n--- HR aggregates (HR has no key) ---")
    combined = aggregate()
    print("\n--- MANAGERS reveal only the totals ---")
    reveal(combined)
    print("\n--- HR looks at integrity data ---")
    show_hashes()
    print("\n--- ACCESS CONTROL ---")
    allowed("hr", "reveal")
    allowed("employee", "aggregate")
    print("\ncheck: real total =", sum(answers.values()),
          " real average = %.2f" % (sum(answers.values()) / len(answers)))
    print("=" * 66)


def menu():
    combined = None
    while True:
        print("\nSECUREPOLL")
        print("1 Submit response | 2 HR aggregate | 3 Manager reveal"
              " | 4 Show hashes | 5 Reset | 6 Exit")
        choice = input("Input Choice: ").strip()
        if choice == "1":
            submit(input("Employee ID: ").strip() or "E001",
                   input("Score 1..5: ").strip() or "3")
        elif choice == "2":
            combined = aggregate()
        elif choice == "3":
            reveal(combined)
        elif choice == "4":
            show_hashes()
        elif choice == "5":
            for path in [data_file, "poll_key.json"]:
                if os.path.exists(path):
                    os.remove(path)
            print("reset - restart the program")
            return
        elif choice == "6":
            return


if len(sys.argv) > 1 and sys.argv[1] == "reset":
    for path in [data_file, "poll_key.json"]:
        if os.path.exists(path):
            os.remove(path)
    print("reset")
    sys.exit(0)

load()
public_key = keygen()
private_secret = public_key.pop("secret")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "demo":
        demo()
    else:
        menu()
