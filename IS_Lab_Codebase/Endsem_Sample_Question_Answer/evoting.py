# SecureVote - Information Security Lab (ICT 3141) end-sem answer
# AES-256 / CBC | SHA-512 | ElGamal signature | RSA-2048 key wrap
# Paillier additive homomorphic tally | SSE searchable index
# Shamir 2-of-3 threshold decryption | role based access control
#
# RUN
#   python evoting.py            interactive menu  <- this is what is marked
#   python evoting.py demo       full run, no typing, prints every output
#   python evoting.py netdemo    real TCP client-server submission
#   python evoting.py server     listen on 127.0.0.1:9099  (terminal 1)
#   python evoting.py client     submit a ballot over TCP   (terminal 2)
#   python evoting.py reset      delete the stored files and start clean

import os
import sys
import json
import time
import hmac
import socket
import random
import hashlib
import threading
from datetime import datetime, timedelta

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Util.number import getPrime, GCD
from Crypto.PublicKey import RSA

try:
    sys.stdout.reconfigure(errors="replace")
except Exception:
    pass

# ===== SETTINGS - change these to match the question =====
system_name = "SecureVote"
record_word = "ballot"
roles = {
    "voter": ["cast", "view_own"],
    "server": ["verify", "search", "view_all", "tamper_test"],
    "tally": ["aggregate", "threshold_decrypt"],
    "auditor": ["view_hashes", "audit"]
}
aes_bits = 256                 # 128 / 192 / 256
rsa_bits = 2048                # 4096 in the question, 2048 keeps keygen fast
elgamal_bits = 256             # size of the ElGamal signature prime p
paillier_bits = 512            # size of the Paillier modulus n
threshold_t = 2                # shares needed to decrypt the final tally
threshold_n = 3                # shares handed out
voting_opens = "2000-01-01 00:00:00"
voting_closes = "2099-12-31 23:59:59"
candidates = {1: "Party A", 2: "Party B", 3: "Party C"}
host, port = "127.0.0.1", 9099
# ===== END SETTINGS =====

records = {}                   # ballot_id -> stored envelope
search_index = {}              # HMAC token (hex) -> [encrypted ballot ids]
voter_keys = {}                # voter name -> ElGamal keypair
record_file = "ballots.json"
key_file = "keys.json"
log_file = "audit.log"
MAX_VOTERS = 10 ** 6           # base used to pack the per-candidate counters


def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def short(text, n=48):
    text = str(text)
    return text if len(text) <= n else text[:n] + "..."


def hexs(value):
    if isinstance(value, bytes):
        return value.hex().upper()
    if isinstance(value, int):
        return hex(value)
    return str(value)


# ---------- Encryption and Decryption (ED component) ----------

def new_aes_key():
    return get_random_bytes(aes_bits // 8)


def encrypt_data(key, data):
    # AES-256 in CBC mode: fresh random IV every time, PKCS#7 padding.
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv, cipher.encrypt(pad(data.encode(), AES.block_size))


def decrypt_data(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # errors="replace" so a tampered block prints instead of crashing the demo
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode(errors="replace")


def server_rsa_keys():
    # The Election Commission key pair. Cached in a file so a rerun is instant.
    if os.path.exists("ec_private.pem"):
        key = RSA.import_key(open("ec_private.pem", "rb").read())
    else:
        key = RSA.generate(rsa_bits)
        open("ec_private.pem", "wb").write(key.export_key())
        open("ec_public.pem", "wb").write(key.publickey().export_key())
    return key, key.publickey()


def wrap_key(aes_key, public_key):
    # The AES session key travels encrypted under the RSA public key.
    return PKCS1_OAEP.new(public_key).encrypt(aes_key)


def unwrap_key(blob, private_key):
    return PKCS1_OAEP.new(private_key).decrypt(blob)


# ---------- Hashing (Hash component) ----------

def hash_data(data):
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha512(data).hexdigest()


# ---------- Digital Signature (DSS component) : ElGamal ----------

def elgamal_keygen():
    # p prime, g generator, x private, y = g^x mod p
    p = getPrime(elgamal_bits)
    g = 2
    x = random.randrange(2, p - 2)
    y = pow(g, x, p)
    return {"p": p, "g": g, "y": y, "x": x}


def sign_hash(digest_hex, key):
    p, g, x = key["p"], key["g"], key["x"]
    h = int(digest_hex, 16) % (p - 1)
    while True:
        k = random.randrange(2, p - 2)
        if GCD(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    s = ((h - x * r) * pow(k, -1, p - 1)) % (p - 1)
    return r, s


def verify_hash(digest_hex, signature, key):
    p, g, y = key["p"], key["g"], key["y"]
    r, s = signature
    if not 0 < r < p:
        return False
    h = int(digest_hex, 16) % (p - 1)
    left = pow(g, h, p)
    right = (pow(y, r, p) * pow(r, s, p)) % p
    return left == right


# ---------- Partial homomorphic encryption (Paillier) ----------

def paillier_keygen():
    # cached in a file so ballots cast in an earlier run can still be tallied
    if os.path.exists("paillier_key.json"):
        return {k: int(v) for k, v in json.load(open("paillier_key.json")).items()}
    p = getPrime(paillier_bits // 2)
    q = getPrime(paillier_bits // 2)
    while p == q:
        q = getPrime(paillier_bits // 2)
    n = p * q
    key = {"n": n, "g": n + 1, "nn": n * n, "lam": (p - 1) * (q - 1)}
    json.dump({k: str(v) for k, v in key.items()}, open("paillier_key.json", "w"))
    return key


def paillier_encrypt(m, pub):
    # c = (1 + m*n) * r^n  mod n^2
    n, nn = pub["n"], pub["nn"]
    r = random.randrange(1, n)
    while GCD(r, n) != 1:
        r = random.randrange(1, n)
    return ((1 + m * n) * pow(r, n, nn)) % nn


def paillier_add(c1, c2, pub):
    # multiplying ciphertexts adds the plaintexts - this is the whole point
    return (c1 * c2) % pub["nn"]


def paillier_decrypt(c, pub, lam):
    n, nn = pub["n"], pub["nn"]
    u = (pow(c, lam, nn) - 1) // n
    return (u * pow(lam, -1, n)) % n


# ---------- Threshold decryption (Shamir t-of-n over lambda) ----------

def shamir_split(secret, t, n, prime):
    coeffs = [secret] + [random.randrange(1, prime) for _ in range(t - 1)]
    shares = []
    for i in range(1, n + 1):
        y = sum(c * pow(i, j, prime) for j, c in enumerate(coeffs)) % prime
        shares.append((i, y))
    return shares


def shamir_combine(shares, prime):
    total = 0
    for xi, yi in shares:
        num, den = 1, 1
        for xj, _ in shares:
            if xi != xj:
                num = (num * -xj) % prime
                den = (den * (xi - xj)) % prime
        total = (total + yi * num * pow(den, -1, prime)) % prime
    return total


# ---------- Searchable encryption index (Search component) ----------

def search_token(label):
    # HMAC with the index key: the server can match tokens but cannot read labels
    return hmac.new(index_key, label.lower().encode(), hashlib.sha256).hexdigest()


def index_add(label, record_id):
    token = search_token(label)
    iv, ct = encrypt_data(index_key, record_id)
    search_index.setdefault(token, []).append([iv.hex(), ct.hex()])


def index_lookup(label):
    hits = []
    for iv_hex, ct_hex in search_index.get(search_token(label), []):
        hits.append(decrypt_data(index_key, bytes.fromhex(iv_hex), bytes.fromhex(ct_hex)))
    return sorted(set(hits))


def minute_bucket(stamp):
    return "time:" + stamp[:16]


def search_by_constituency(cid):
    return index_lookup("const:" + str(cid))


def search_by_time_range(start, end):
    # expand the range into one-minute buckets and look each one up
    t0 = datetime.strptime(start, "%Y-%m-%d %H:%M")
    t1 = datetime.strptime(end, "%Y-%m-%d %H:%M")
    found = []
    while t0 <= t1:
        found += index_lookup(minute_bucket(t0.strftime("%Y-%m-%d %H:%M")))
        t0 += timedelta(minutes=1)
    return sorted(set(found))


# ---------- Saving and loading ----------

def save_all():
    json.dump(records, open(record_file, "w"), indent=2)
    json.dump(search_index, open("index.json", "w"), indent=2)
    json.dump({name: {k: v for k, v in key.items()} for name, key in voter_keys.items()},
              open(key_file, "w"), indent=2)


def load_all():
    global records, search_index, voter_keys
    if os.path.exists(record_file):
        records = json.load(open(record_file))
    if os.path.exists("index.json"):
        search_index = json.load(open("index.json"))
    if os.path.exists(key_file):
        voter_keys = json.load(open(key_file))


def get_voter_key(name):
    if name not in voter_keys:
        voter_keys[name] = elgamal_keygen()
        log_action(name, "elgamal key pair generated")
    return voter_keys[name]


# ---------- Audit log ----------

def log_action(who, what):
    line = "%s | %s | %s" % (timestamp(), who, what)
    open(log_file, "a").write(line + "\n")


def show_log():
    if not os.path.exists(log_file):
        print("audit log is empty")
        return
    for line in open(log_file):
        print(line.rstrip())


# ---------- Access control ----------

def check_permission(role, action):
    if action not in roles.get(role, []):
        print("ACCESS DENIED:", role, "cannot", action)
        log_action(role, "DENIED " + action)
        return False
    return True


# ---------- Client side : cast a ballot ----------

def cast_ballot(voter, ballot_id, candidate_id, constituency_id, when=None):
    if not check_permission("voter", "cast"):
        return None

    ballot = "CandidateID=%s;ConstituencyID=%s" % (candidate_id, constituency_id)
    print("Ballot UTF-8:", ballot)

    digest = hash_data(ballot)                              # 1 SHA-512 for integrity
    print("Output SHA-512(hex):", digest[:64])
    print("                    ", digest[64:])

    aes_key = new_aes_key()                                 # 2 AES-256-CBC
    iv, ct = encrypt_data(aes_key, ballot)
    print("Output IV(hex):", hexs(iv))
    print("Output AES-256-CBC CT(hex):", hexs(ct))

    wrapped = wrap_key(aes_key, ec_public)                  # 3 RSA key wrap
    print("Output AES key wrapped with RSA-%d: [%d-byte ciphertext] %s"
          % (rsa_bits, len(wrapped), short(hexs(wrapped), 32)))

    key = get_voter_key(voter)                              # 4 ElGamal signature
    signature = sign_hash(digest, key)
    print("Output ElGamal signature (r, s): (%d, %d)" % signature)

    vote_ct = paillier_encrypt(int(candidate_id), pail_pub)        # 5 Paillier vote
    packed_ct = paillier_encrypt(MAX_VOTERS ** int(candidate_id), pail_pub)
    print("Output Paillier vote CT(hex):", short(hexs(vote_ct), 24))

    stamp = when or timestamp()                             # 6 trusted timestamp
    print("Timestamp:", stamp)

    records[ballot_id] = {
        "voter": voter,
        "constituency": str(constituency_id),
        "iv": iv.hex(),
        "ciphertext": ct.hex(),
        "wrapped_key": wrapped.hex(),
        "hash": digest,
        "signature": [str(signature[0]), str(signature[1])],
        "vote_ct": str(vote_ct),
        "packed_ct": str(packed_ct),
        "timestamp": stamp,
        "status": "submitted"
    }
    index_add("const:" + str(constituency_id), ballot_id)    # 7 searchable metadata
    index_add(minute_bucket(stamp), ballot_id)
    save_all()
    log_action(voter, "cast " + ballot_id)
    print("Output:", ballot_id, "submitted; searchable constituency/time metadata indexed")
    return ballot_id


# ---------- Server side : verify a ballot ----------

def within_voting_period(stamp):
    return voting_opens <= stamp <= voting_closes


def verify_ballot(ballot_id):
    if not check_permission("server", "verify"):
        return False
    if ballot_id not in records:
        print("no such", record_word, ":", ballot_id)
        return False

    row = records[ballot_id]
    aes_key = unwrap_key(bytes.fromhex(row["wrapped_key"]), ec_private)
    print("Output: RSA private-key unwrap successful")

    try:
        ballot = decrypt_data(aes_key, bytes.fromhex(row["iv"]), bytes.fromhex(row["ciphertext"]))
    except ValueError:
        ballot = ""                      # padding destroyed -> definitely tampered
    print("Decrypted", record_word + ":", ballot or "<unreadable, padding broken>")

    key = voter_keys[row["voter"]]
    sig = (int(row["signature"][0]), int(row["signature"][1]))
    sig_ok = verify_hash(row["hash"], sig, key)
    print("Output: ElGamal signature", "valid" if sig_ok else "INVALID")

    hash_ok = hash_data(ballot) == row["hash"]
    print("Output: recomputed SHA-512", "matches stored hash" if hash_ok else "DOES NOT MATCH")

    time_ok = within_voting_period(row["timestamp"])
    print("Output: timestamp", "within voting period" if time_ok else "OUTSIDE voting period")

    accepted = sig_ok and hash_ok and time_ok
    row["status"] = "accepted" if accepted else "rejected"
    save_all()
    log_action("server", "verify %s -> %s" % (ballot_id, row["status"]))
    print("Output:", ballot_id, row["status"] + "; Paillier vote remains encrypted")
    return accepted


def tamper_ballot(ballot_id):
    # Flip one byte of the stored ciphertext to prove the hash check works.
    if not check_permission("server", "tamper_test"):
        return
    row = records[ballot_id]
    raw = bytearray(bytes.fromhex(row["ciphertext"]))
    raw[0] ^= 0x01                       # first block: garbles the text, padding survives
    row["ciphertext"] = bytes(raw).hex()
    save_all()
    print("tampered with stored ciphertext of", ballot_id, "- now re-verify it")
    log_action("server", "tamper test on " + ballot_id)


# ---------- Tally authority : homomorphic aggregate + threshold decrypt ----------

def aggregate(ids=None):
    if not check_permission("tally", "aggregate"):
        return None
    ids = ids or [k for k, v in records.items() if v["status"] == "accepted"]
    if not ids:
        print("nothing accepted yet - verify the ballots first")
        return None

    total_votes = paillier_encrypt(0, pail_pub)
    total_packed = paillier_encrypt(0, pail_pub)
    for bid in ids:
        total_votes = paillier_add(total_votes, int(records[bid]["vote_ct"]), pail_pub)
        total_packed = paillier_add(total_packed, int(records[bid]["packed_ct"]), pail_pub)

    print("Aggregated", len(ids), "encrypted votes:", ", ".join(ids))
    print("Output: product of ciphertexts mod n^2 =", short(hexs(total_votes), 24))
    print("Output: only the combined ciphertext is submitted for threshold decryption")
    return total_votes, total_packed


def threshold_decrypt(combined):
    if not check_permission("tally", "threshold_decrypt"):
        return None
    total_votes, total_packed = combined

    # lambda is never held by one authority: it is split into n Shamir shares
    prime = getPrime(pail_pub["n"].bit_length() + 16)
    shares = shamir_split(pail_priv_lambda, threshold_t, threshold_n, prime)
    print("Threshold scheme: %d-of-%d Shamir shares of the Paillier private exponent"
          % (threshold_t, threshold_n))

    presented = shares[:threshold_t]
    print("Threshold authorization: %d shares presented -> sufficient" % len(presented))
    lam = shamir_combine(presented, prime)
    if lam != pail_priv_lambda:
        print("share reconstruction FAILED")
        return None

    sum_of_ids = paillier_decrypt(total_votes, pail_pub, lam)
    packed = paillier_decrypt(total_packed, pail_pub, lam)
    print("Output: decrypted sum of candidate IDs =", sum_of_ids)
    print("Output: per-candidate counts (individual votes never decrypted)")
    for cid, name in sorted(candidates.items()):
        count = (packed // (MAX_VOTERS ** cid)) % MAX_VOTERS
        print("   candidate %d %-10s count = %d" % (cid, name, count))
    log_action("tally", "threshold decrypt of the aggregate")
    return packed


def show_single_share_fails():
    prime = getPrime(pail_pub["n"].bit_length() + 16)
    shares = shamir_split(pail_priv_lambda, threshold_t, threshold_n, prime)
    guess = shamir_combine(shares[:1], prime)
    print("One authority alone reconstructs lambda =", short(guess, 20))
    print("correct lambda                          =", short(pail_priv_lambda, 20))
    print("-> a single authority learns nothing, which is what threshold means")


# ---------- Views ----------

def view_own(voter):
    if not check_permission("voter", "view_own"):
        return
    for bid, row in records.items():
        if row["voter"] == voter:
            print(bid, "|", row["constituency"], "|", row["timestamp"], "|", row["status"])


def view_all():
    if not check_permission("server", "view_all"):
        return
    print("%-8s %-10s %-6s %-20s %s" % ("BALLOT", "VOTER", "CONST", "TIMESTAMP", "STATUS"))
    for bid, row in records.items():
        print("%-8s %-10s %-6s %-20s %s" % (bid, row["voter"], row["constituency"],
                                            row["timestamp"], row["status"]))


def show_hashes():
    if not check_permission("auditor", "view_hashes"):
        return
    for bid, row in records.items():
        print(bid, ":", row["hash"][:32] + "...", "| sig r =", short(row["signature"][0], 16))


# ---------- Client-Server over TCP (Client-Server component) ----------

def send_frame(sock, obj):
    data = json.dumps(obj).encode()
    sock.sendall(len(data).to_bytes(4, "big") + data)


def recv_exact(sock, count):
    buf = b""
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf


def recv_frame(sock):
    size = int.from_bytes(recv_exact(sock, 4), "big")
    return json.loads(recv_exact(sock, size).decode())


def run_server(once=False):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(5)
    print("[server] listening on %s:%d" % (host, port))
    while True:
        conn, addr = srv.accept()
        try:
            msg = recv_frame(conn)
            print("[server] ballot received from", addr[0])
            records[msg["ballot_id"]] = msg["envelope"]
            voter_keys[msg["envelope"]["voter"]] = msg["voter_key"]
            for token, entries in msg["index"].items():
                search_index.setdefault(token, []).extend(entries)
            save_all()
            ok = verify_ballot(msg["ballot_id"])
            send_frame(conn, {"ballot_id": msg["ballot_id"], "accepted": bool(ok)})
        except Exception as exc:
            send_frame(conn, {"error": str(exc)})
        finally:
            conn.close()
        if once:
            break
    srv.close()


def run_client(voter="alice", ballot_id="N001", candidate_id=1, constituency_id=101):
    before = dict(search_index)
    cast_ballot(voter, ballot_id, candidate_id, constituency_id)
    fresh = {t: e for t, e in search_index.items() if before.get(t) != e}
    sock = socket.create_connection((host, port), timeout=10)
    send_frame(sock, {"ballot_id": ballot_id,
                      "envelope": records[ballot_id],
                      "voter_key": voter_keys[voter],
                      "index": fresh})
    print("[client] server replied:", recv_frame(sock))
    sock.close()


def netdemo():
    thread = threading.Thread(target=run_server, kwargs={"once": True}, daemon=True)
    thread.start()
    time.sleep(0.5)
    run_client()
    thread.join(timeout=5)


# ---------- Menus ----------

def voter_menu():
    while True:
        print("\nVOTER MENU: 1 Cast vote | 2 View my ballots | 3 Back")
        choice = input("Input Choice: ").strip()
        if choice == "1":
            bid = input("Ballot ID: ").strip()
            cand = input("Candidate ID: ").strip()
            const = input("Constituency ID: ").strip()
            cast_ballot(input("Voter name: ").strip() or "alice", bid, cand, const)
        elif choice == "2":
            view_own(input("Voter name: ").strip() or "alice")
        elif choice == "3":
            return


def server_menu():
    while True:
        print("\nSERVER MENU: 1 Verify ballot | 2 Search index | 3 All ballots"
              " | 4 Tamper test | 5 Back")
        choice = input("Input Choice: ").strip()
        if choice == "1":
            verify_ballot(input("Ballot ID: ").strip())
        elif choice == "2":
            print("  1 by constituency   2 by time range")
            if input("  > ").strip() == "1":
                print("Output IDs:", ", ".join(search_by_constituency(
                    input("Constituency ID: ").strip())) or "none")
            else:
                start = input("From (YYYY-MM-DD HH:MM): ").strip()
                end = input("To   (YYYY-MM-DD HH:MM): ").strip()
                print("Output IDs:", ", ".join(search_by_time_range(start, end)) or "none")
        elif choice == "3":
            view_all()
        elif choice == "4":
            tamper_ballot(input("Ballot ID: ").strip())
        elif choice == "5":
            return


def tally_menu():
    combined = None
    while True:
        print("\nTALLY MENU: 1 Aggregate | 2 Threshold decrypt | 3 One share alone | 4 Back")
        choice = input("Input Choice: ").strip()
        if choice == "1":
            combined = aggregate()
        elif choice == "2":
            if combined is None:
                print("aggregate first")
            else:
                threshold_decrypt(combined)
        elif choice == "3":
            show_single_share_fails()
        elif choice == "4":
            return


def auditor_menu():
    while True:
        print("\nAUDITOR MENU: 1 Hashes and signatures | 2 Audit log | 3 Back")
        choice = input("Input Choice: ").strip()
        if choice == "1":
            show_hashes()
        elif choice == "2":
            show_log()
        elif choice == "3":
            return


def menu():
    while True:
        print("\n" + system_name.upper())
        print("MAIN MENU: 1 Voter | 2 Election Server | 3 Tally Authority"
              " | 4 Auditor | 5 Exit")
        choice = input("Input Choice: ").strip()
        if choice == "1":
            voter_menu()
        elif choice == "2":
            server_menu()
        elif choice == "3":
            tally_menu()
        elif choice == "4":
            auditor_menu()
        elif choice == "5":
            print("Exit")
            return
        else:
            print("invalid choice")


# ---------- Full run with no typing ----------

def demo():
    print("=" * 70)
    print(system_name, "- full demonstration")
    print("=" * 70)

    print("\n--- VOTER: cast ballot B001 ---")
    cast_ballot("alice", "B001", 1, 101)
    print("\n--- VOTER: cast ballot B002 ---")
    cast_ballot("bob", "B002", 1, 102)
    print("\n--- VOTER: cast ballot B003 ---")
    cast_ballot("carol", "B003", 2, 101)

    print("\n--- SERVER: verify each ballot ---")
    for bid in ["B001", "B002", "B003"]:
        print("[" + bid + "]")
        verify_ballot(bid)

    print("\n--- SERVER: searchable index ---")
    print("constituency 101 ->", ", ".join(search_by_constituency(101)))
    print("constituency 102 ->", ", ".join(search_by_constituency(102)))
    now = datetime.now()
    start = (now - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M")
    end = (now + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M")
    print("time range %s .. %s -> %s" % (start, end, ", ".join(search_by_time_range(start, end))))
    print("the server matched HMAC tokens; it never saw 'const:101' in the clear")

    print("\n--- SERVER: tamper test ---")
    tamper_ballot("B003")
    verify_ballot("B003")

    print("\n--- TALLY: homomorphic aggregate ---")
    combined = aggregate(["B001", "B002"])

    print("\n--- TALLY: threshold decryption ---")
    threshold_decrypt(combined)
    print()
    show_single_share_fails()

    print("\n--- AUDITOR: hashes only ---")
    show_hashes()

    print("\n--- ACCESS CONTROL ---")
    check_permission("auditor", "cast")
    check_permission("voter", "threshold_decrypt")

    print("\n--- CLIENT-SERVER over TCP ---")
    netdemo()

    print("\n--- AUDIT LOG ---")
    show_log()
    print("\n" + "=" * 70)
    print("demonstration finished")


def reset():
    for path in [record_file, key_file, log_file, "index.json",
                 "ec_private.pem", "ec_public.pem", "paillier_key.json"]:
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            pass
    print("stored files removed")


# ---------- Start up ----------

if len(sys.argv) > 1 and sys.argv[1] == "reset":
    reset()
    sys.exit(0)

load_all()
index_key = hashlib.sha256(b"SecureVote-index-key").digest()
ec_private, ec_public = server_rsa_keys()
pail_pub = paillier_keygen()
pail_priv_lambda = pail_pub.pop("lam")

if __name__ == "__main__":
    arg = sys.argv[1] if len(sys.argv) > 1 else ""
    if arg == "demo":
        demo()
    elif arg == "netdemo":
        netdemo()
    elif arg == "server":
        run_server()
    elif arg == "client":
        run_client(*sys.argv[2:])
    else:
        menu()
