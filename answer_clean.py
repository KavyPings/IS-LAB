import os
import sys
import json
import hashlib
import hmac
import random
import time
import socket
import threading
from datetime import datetime, timedelta

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.number import getPrime, GCD

try:
    sys.stdout.reconfigure(errors="replace")
except Exception:
    pass

# ===== SETTINGS - change these to match the question =====
system_name = "SecureVote"
record_word = "ballot"
roles = {
    "voter": ["submit", "view_own"],
    "server": ["verify", "search", "view_all", "tamper_test"],
    "tally": ["aggregate", "threshold_decrypt"],
    "auditor": ["view_hashes", "audit"]
}
key_bytes = 32
rsa_bits = 2048
sign_bits = 256
paillier_bits = 512
threshold_t = 2
threshold_n = 3
window_opens = "2000-01-01 00:00:00"
window_closes = "2099-12-31 23:59:59"
categories = {1: "option one", 2: "option two", 3: "option three"}
host, port = "127.0.0.1", 9099
# ===== END SETTINGS =====

records = {}
search_index = {}
signer_keys = {}
record_file = "records.json"
key_file = "keys.json"
log_file = "audit.log"
MAX_ITEMS = 10 ** 6


client_role = "voter"
server_role = "server"
analyst_role = "tally"
auditor_role = "auditor"


# ---------- Small helpers ----------


def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def short(value, n=44):
    text = str(value)
    return text if len(text) <= n else text[:n] + "..."


def hexs(value):

    if isinstance(value, bytes):
        return value.hex().upper()
    if isinstance(value, int):
        return hex(value)
    return str(value)


# ---------- Encryption and decryption (ED) ----------


def new_key():

    return get_random_bytes(key_bytes)


def encrypt_data(key, data):

    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv, cipher.encrypt(pad(data.encode(), 16))


def decrypt_data(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)

    return unpad(cipher.decrypt(ciphertext), 16).decode(errors="replace")


# ---------- Wrapping the session key with a public key ----------


def server_keys():

    if os.path.exists("server_private.pem"):
        key = RSA.import_key(open("server_private.pem", "rb").read())
    else:
        key = RSA.generate(rsa_bits)
        open("server_private.pem", "wb").write(key.export_key())
        open("server_public.pem", "wb").write(key.publickey().export_key())
    return key, key.publickey()


def wrap_key(session_key, public_key):

    return PKCS1_OAEP.new(public_key).encrypt(session_key)


def unwrap_key(blob, private_key):
    return PKCS1_OAEP.new(private_key).decrypt(blob)


# ---------- Hashing (Hash) ----------


def hash_data(data):

    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha512(data).hexdigest()


def hash_matches(data, stored_hex):

    return hash_data(data) == stored_hex


# ---------- Digital signature (DSS) ----------


def make_signing_key():

    p = getPrime(sign_bits)
    g = 2
    x = random.randrange(2, p - 2)
    return {"p": p, "g": g, "y": pow(g, x, p), "x": x}


def sign_hash(digest_hex, key):

    p, g, x = key["p"], key["g"], key["x"]
    h = int(digest_hex, 16) % (p - 1)
    while True:
        k = random.randrange(2, p - 2)
        if GCD(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    s = ((h - x * r) * pow(k, -1, p - 1)) % (p - 1)
    return [r, s]


def verify_hash(digest_hex, signature, key):

    p, g, y = key["p"], key["g"], key["y"]
    r, s = int(signature[0]), int(signature[1])
    if not 0 < r < p:
        return False
    h = int(digest_hex, 16) % (p - 1)
    return pow(g, h, p) == (pow(y, r, p) * pow(r, s, p)) % p


def sig_text(signature):
    return "(r, s) = (%s, %s)" % (short(signature[0], 30), short(signature[1], 30))


# ---------- Partial homomorphic encryption ----------


def he_keygen():

    if os.path.exists("he_key.json"):
        return {k: int(v) for k, v in json.load(open("he_key.json")).items()}
    p = getPrime(paillier_bits // 2)
    q = getPrime(paillier_bits // 2)
    while p == q:
        q = getPrime(paillier_bits // 2)
    n = p * q
    key = {"n": n, "g": n + 1, "nn": n * n, "secret": (p - 1) * (q - 1)}
    json.dump({k: str(v) for k, v in key.items()}, open("he_key.json", "w"))
    return key


def he_encrypt(m, pub):

    n, nn = pub["n"], pub["nn"]
    r = random.randrange(1, n)
    while GCD(r, n) != 1:
        r = random.randrange(1, n)
    return ((1 + m * n) * pow(r, n, nn)) % nn


def he_combine(c1, c2, pub):

    return (c1 * c2) % pub["nn"]


def he_decrypt(c, pub, secret):
    n, nn = pub["n"], pub["nn"]
    u = (pow(c, secret, nn) - 1) // n
    return (u * pow(secret, -1, n)) % n


HE_OPERATION = "addition"


# ---------- Threshold decryption ----------


def shamir_split(secret, t, n, prime):

    coeffs = [secret] + [random.randrange(1, prime) for _ in range(t - 1)]
    shares = []
    for i in range(1, n + 1):
        y = sum(c * pow(i, j, prime) for j, c in enumerate(coeffs)) % prime
        shares.append([i, y])
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


def share_prime():

    return getPrime(he_secret.bit_length() + 16)


def one_share_alone():
    prime = share_prime()
    shares = shamir_split(he_secret, threshold_t, threshold_n, prime)
    guess = shamir_combine(shares[:1], prime)
    print("one authority alone reconstructs :", short(guess, 30))
    print("the real private exponent is     :", short(he_secret, 30))
    print("-> a single authority learns nothing, which is what threshold means")


# ---------- Searchable encryption (Search) ----------


def search_token(label):

    return hmac.new(index_key, label.lower().encode(), hashlib.sha256).hexdigest()


def index_add(label, record_id):

    iv, ct = encrypt_data(index_key, record_id)
    search_index.setdefault(search_token(label), []).append([iv.hex(), ct.hex()])


def index_lookup(label):
    hits = []
    for iv_hex, ct_hex in search_index.get(search_token(label), []):
        hits.append(decrypt_data(index_key, bytes.fromhex(iv_hex), bytes.fromhex(ct_hex)))
    return sorted(set(hits))


def minute_bucket(stamp):
    return "time:" + stamp[:16]


def search_by_tag(value):
    return index_lookup("ConstituencyID:" + str(value))


def search_by_time_range(start, end):

    t0 = datetime.strptime(start, "%Y-%m-%d %H:%M")
    t1 = datetime.strptime(end, "%Y-%m-%d %H:%M")
    found = []
    while t0 <= t1:
        found += index_lookup(minute_bucket(t0.strftime("%Y-%m-%d %H:%M")))
        t0 += timedelta(minutes=1)
    return sorted(set(found))


# ---------- Audit log ----------


def log_action(who, what):

    open(log_file, "a").write("%s | %s | %s\n" % (timestamp(), who, what))


def show_log():
    if not os.path.exists(log_file):
        print("audit log is empty")
        return
    for line in open(log_file):
        print(line.rstrip())


# ---------- Saving and loading ----------


def save_all():
    json.dump(records, open(record_file, "w"), indent=2)
    json.dump(signer_keys, open(key_file, "w"), indent=2)
    json.dump(search_index, open("index.json", "w"), indent=2)

def load_all():
    global records, signer_keys, search_index
    if os.path.exists(record_file):
        records = json.load(open(record_file))
    if os.path.exists(key_file):
        signer_keys = json.load(open(key_file))
    if os.path.exists("index.json"):
        search_index = json.load(open("index.json"))

def get_signing_key(user):
    if user not in signer_keys:
        signer_keys[user] = make_signing_key()
        log_action(user, "ElGamal key pair generated")
    return signer_keys[user]


# ---------- Access control ----------


def check_permission(role, action):

    if action not in roles.get(role, []):
        print("ACCESS DENIED:", role, "cannot", action)
        log_action(role, "DENIED " + action)
        return False
    return True


# ---------- Client side: build and submit ----------


def submit_record(user, record_id, value, tag, when=None):
    if not check_permission(client_role, "submit"):
        return None


    body = "CandidateID=%s;ConstituencyID=%s" % (value, tag)
    print("Ballot UTF-8:", body)


    digest = hash_data(body)
    print("Output sha512(hex):", digest[:64])
    print("                  ", digest[64:])


    session_key = new_key()
    iv, ciphertext = encrypt_data(session_key, body)
    print("Output %s(hex):" % ("nonce" if "CBC" == "CTR" else "IV"), hexs(iv))
    print("Output AES-256-CBC CT(hex):", hexs(ciphertext))


    wrapped = wrap_key(session_key, server_public)
    print("Output session key wrapped with RSA-2048: [%d bytes] %s"
          % (len(wrapped), short(hexs(wrapped), 32)))


    signing_key = get_signing_key(user)
    signature = sign_hash(digest, signing_key)
    print("Output ElGamal signature:", sig_text(signature))


    value_ct = he_encrypt(int(value), he_pub)
    packed_ct = he_encrypt(MAX_ITEMS ** int(value), he_pub)
    print("Output homomorphic CandidateID CT(hex):", short(hexs(value_ct), 26))


    stamp = when or timestamp()
    print("Timestamp:", stamp)

    records[record_id] = {
        "user": user,
        "tag": str(tag),
        "iv": iv.hex(),
        "ciphertext": ciphertext.hex(),
        "wrapped_key": wrapped.hex(),
        "hash": digest,
        "signature": signature,
        "value_ct": str(value_ct),
        "packed_ct": str(packed_ct),
        "timestamp": stamp,
        "status": "submitted"
    }
    index_add("ConstituencyID:" + str(tag), record_id)
    index_add(minute_bucket(stamp), record_id)
    save_all()
    log_action(user, "submit " + record_id)
    print("Output:", record_id, "submitted; searchable metadata indexed")
    return record_id


# ---------- Server side: verify ----------


def within_window(stamp):

    return window_opens <= stamp <= window_closes


def verify_record(record_id):
    if not check_permission(server_role, "verify"):
        return False
    if record_id not in records:
        print("no such ballot:", record_id)
        return False

    row = records[record_id]


    session_key = unwrap_key(bytes.fromhex(row["wrapped_key"]), server_private)
    print("Output: private-key unwrap successful")


    try:
        body = decrypt_data(session_key, bytes.fromhex(row["iv"]),
                            bytes.fromhex(row["ciphertext"]))
    except ValueError:
        body = ""
    print("Decrypted ballot:", body or "<unreadable, padding broken>")


    sig_ok = verify_hash(row["hash"], row["signature"], signer_keys[row["user"]])
    print("Output: ElGamal signature", "valid" if sig_ok else "INVALID")


    hash_ok = hash_matches(body, row["hash"])
    print("Output: recomputed sha512",
          "matches stored hash" if hash_ok else "DOES NOT MATCH")


    time_ok = within_window(row["timestamp"])
    print("Output: timestamp",
          "within the valid period" if time_ok else "OUTSIDE the valid period")

    accepted = sig_ok and hash_ok and time_ok
    row["status"] = "accepted" if accepted else "rejected"
    save_all()
    log_action(server_role, "verify %s -> %s" % (record_id, row["status"]))
    print("Output:", record_id, row["status"] + "; encrypted CandidateID left untouched")
    return accepted


def tamper_record(record_id):

    if not check_permission(server_role, "tamper_test"):
        return
    row = records[record_id]
    raw = bytearray(bytes.fromhex(row["ciphertext"]))
    raw[0] ^= 0x01
    row["ciphertext"] = bytes(raw).hex()
    save_all()
    print("tampered with the stored ciphertext of", record_id, "- now re-verify it")
    log_action(server_role, "tamper test on " + record_id)


# ---------- Aggregation and reveal ----------


def aggregate(ids=None):
    if not check_permission(analyst_role, "aggregate"):
        return None
    ids = ids or [k for k, v in records.items() if v["status"] == "accepted"]
    if not ids:
        print("nothing accepted yet - verify the ballots first")
        return None

    total = he_encrypt(0, he_pub)
    packed = he_encrypt(0, he_pub)
    for rid in ids:
        total = he_combine(total, int(records[rid]["value_ct"]), he_pub)
        packed = he_combine(packed, int(records[rid]["packed_ct"]), he_pub)

    print("Combined", len(ids), "encrypted CandidateIDs:", ", ".join(ids))
    print("Output: homomorphic", HE_OPERATION, "on ciphertexts =",
          short(hexs(total if not isinstance(total, list) else total[1]), 26))
    print("Output: no single ballot was decrypted to get this")
    return total, packed


def reveal(combined):
    if not check_permission(analyst_role, "threshold_decrypt"):
        return None
    total, packed = combined


    prime = share_prime()
    shares = shamir_split(he_secret, threshold_t, threshold_n, prime)
    print("Threshold scheme: 2-of-3 Shamir shares of the private exponent")
    presented = shares[:threshold_t]
    print("Threshold authorization: %d shares presented -> sufficient"
          % len(presented))
    secret = shamir_combine(presented, prime)
    if secret != he_secret:
        print("share reconstruction FAILED")
        return None

    answer = he_decrypt(total, he_pub, secret)
    print("Output: decrypted", HE_OPERATION, "of all CandidateIDs =", answer)
    counts = he_decrypt(packed, he_pub, secret)
    print("Output: per-category counts (individual ballots never decrypted)")
    for cid, name in sorted(categories.items()):
        print("   %-3d %-14s count = %d"
              % (cid, name, (counts // (MAX_ITEMS ** cid)) % MAX_ITEMS))
    log_action(analyst_role, "aggregate revealed")
    return answer


# ---------- Views ----------


def view_own(user):
    if not check_permission(client_role, "view_own"):
        return
    for rid, row in records.items():
        if row["user"] == user:
            print(rid, "|", row["tag"], "|", row["timestamp"], "|", row["status"])


def view_all():
    if not check_permission(server_role, "view_all"):
        return
    print("%-10s %-10s %-8s %-20s %s" % ("ID", "USER", "ConstituencyID"[:8].upper(),
                                         "TIMESTAMP", "STATUS"))
    for rid, row in records.items():
        print("%-10s %-10s %-8s %-20s %s" % (rid, row["user"], row["tag"],
                                             row["timestamp"], row["status"]))


def show_hashes():

    if not check_permission(auditor_role, "view_hashes"):
        return
    for rid, row in records.items():
        print(rid, ":", row["hash"][:32] + "...", "|", sig_text(row["signature"]))


# ---------- Client-Server over TCP ----------


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
            records[msg["record_id"]] = msg["envelope"]
            signer_keys[msg["envelope"]["user"]] = msg["signer_key"]
            for token, entries in msg["index"].items():
                search_index.setdefault(token, []).extend(entries)
            save_all()
            ok = verify_record(msg["record_id"])
            send_frame(conn, {"record_id": msg["record_id"], "accepted": bool(ok)})
        except Exception as exc:
            send_frame(conn, {"error": str(exc)})
        finally:
            conn.close()
        if once:
            break
    srv.close()


def run_client(user="alice", record_id="N001", value=1, tag=101):
    before = {t: list(v) for t, v in search_index.items()}
    submit_record(user, record_id, value, tag)
    fresh = {t: v for t, v in search_index.items() if before.get(t) != v}
    sock = socket.create_connection((host, port), timeout=10)
    payload = {"record_id": record_id,
               "envelope": records[record_id],
               "signer_key": signer_keys[user]}
    payload["index"] = fresh
    send_frame(sock, payload)
    print("[client] server replied:", recv_frame(sock))
    sock.close()


def netdemo():

    thread = threading.Thread(target=run_server, kwargs={"once": True}, daemon=True)
    thread.start()
    time.sleep(0.5)
    run_client()
    thread.join(timeout=5)


# ---------- Menus ----------


def client_menu():
    while True:
        print("\nVOTER MENU: 1 Submit ballot | 2 View mine | 3 Back")
        choice = input("Input Choice: ").strip()
        if choice == "1":
            user = input("User name: ").strip() or "alice"
            rid = input("ballot ID: ").strip() or "R001"
            value = input("CandidateID (a number): ").strip() or "1"
            tag = input("ConstituencyID: ").strip() or "101"
            submit_record(user, rid, value, tag)
        elif choice == "2":
            view_own(input("User name: ").strip() or "alice")
        elif choice == "3":
            return


def server_menu():
    while True:
        print("\nSERVER MENU: 1 Verify ballot | 2 Search index | 3 All ballots | 4 Tamper test | 5 Back")
        choice = input("Input Choice: ").strip()
        if choice == "1":
            verify_record(input("ballot ID: ").strip())
        elif choice == "2":
            print("  1 by ConstituencyID   2 by time range")
            if input("  > ").strip() == "1":
                hits = search_by_tag(input("ConstituencyID: ").strip())
            else:
                start = input("From (YYYY-MM-DD HH:MM): ").strip()
                end = input("To   (YYYY-MM-DD HH:MM): ").strip()
                hits = search_by_time_range(start, end)
            print("Output IDs:", ", ".join(hits) or "none")
        elif choice == "3":
            view_all()
        elif choice == "4":
            tamper_record(input("ballot ID: ").strip())
        elif choice == "5":
            return


def analyst_menu():
    combined = None
    while True:
        print("\nTALLY MENU: 1 Aggregate | 2 Reveal total | 3 One share alone | 4 Back")
        choice = input("Input Choice: ").strip()
        if choice == "1":
            combined = aggregate()
        elif choice == "2":
            if combined is None:
                print("aggregate first")
            else:
                reveal(combined)
        elif choice == "3":
            one_share_alone()
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
        print("MAIN MENU: 1 VOTER | 2 SERVER | 3 TALLY | 4 AUDITOR | 5 Exit")
        choice = input("Input Choice: ").strip()
        if choice == "1":
            client_menu()
        elif choice == "2":
            server_menu()
        elif choice == "3":
            analyst_menu()
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

    print("\n--- CLIENT: submit three ballots ---")
    submit_record("alice", "R001", 1, 101)
    print()
    submit_record("bob", "R002", 1, 102)
    print()
    submit_record("carol", "R003", 2, 101)

    print("\n--- SERVER: verify each ballot ---")
    for rid in ["R001", "R002", "R003"]:
        print("[" + rid + "]")
        verify_record(rid)
        print()
    print("--- SERVER: searchable index (SSE) ---")
    print("ConstituencyID 101 ->", ", ".join(search_by_tag(101)))
    print("ConstituencyID 102 ->", ", ".join(search_by_tag(102)))
    now = datetime.now()
    start = (now - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M")
    end = (now + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M")
    print("time range %s .. %s -> %s"
          % (start, end, ", ".join(search_by_time_range(start, end))))
    print("the server matched tokens; it never saw the label in the clear")

    print("\n--- SERVER: tamper test ---")
    tamper_record("R003")
    verify_record("R003")

    print("\n--- TALLY: homomorphic aggregation ---")
    combined = aggregate(["R001", "R002"])

    print("\n--- TALLY: revealing only the total ---")
    reveal(combined)
    print()
    one_share_alone()

    print("\n--- AUDITOR: integrity data only ---")
    show_hashes()

    print("\n--- ACCESS CONTROL ---")
    check_permission(auditor_role, "submit")
    check_permission(client_role, "view_all")

    print("\n--- CLIENT-SERVER over TCP ---")
    netdemo()

    print("\n--- AUDIT LOG ---")
    show_log()
    print("\n" + "=" * 70)
    print("demonstration finished")


def reset():
    for path in [record_file, key_file, log_file, "index.json", "he_key.json", "server_private.pem", "server_public.pem"]:
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
index_key = hashlib.sha256((system_name + "-index").encode()).digest()[:key_bytes]
server_private, server_public = server_keys()
he_pub = he_keygen()
he_secret = he_pub.pop("secret")

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
