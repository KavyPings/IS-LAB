import os
import sys
import json
import hashlib
import hmac
import random
import socket
from datetime import datetime

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.number import getPrime, GCD

try:
    sys.stdout.reconfigure(errors="replace")
except Exception:
    pass

system_name = "SecureVote"
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
host, port = "127.0.0.1", 9099

records = {}
search_index = {}
signer_keys = {}
record_file = "records.json"
key_file = "keys.json"
log_file = "audit.log"
MAX_ITEMS = 10 ** 6

client_role = "voter"

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

def new_key():
    return get_random_bytes(key_bytes)

def encrypt_data(key, data):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv, cipher.encrypt(pad(data.encode(), 16))

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

def hash_data(data):
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha512(data).hexdigest()

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

def sig_text(signature):
    return "(r, s) = (%s, %s)" % (short(signature[0], 30), short(signature[1], 30))

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

def search_token(label):
    return hmac.new(index_key, label.lower().encode(), hashlib.sha256).hexdigest()

def index_add(label, record_id):
    iv, ct = encrypt_data(index_key, record_id)
    search_index.setdefault(search_token(label), []).append([iv.hex(), ct.hex()])

def minute_bucket(stamp):
    return "time:" + stamp[:16]

def log_action(who, what):
    open(log_file, "a").write("%s | %s | %s\n" % (timestamp(), who, what))

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

def check_permission(subject, action):
    if action not in roles.get(subject, []):
        print("ACCESS DENIED:", subject, "cannot", action)
        log_action(subject, "DENIED " + action)
        return False
    return True

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

    try:
        signing_key = get_signing_key(user)
    except PermissionError as exc:
        print("CANNOT SUBMIT:", exc)
        return None
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

def run_client(user="alice", record_id="N001", value=1, tag=101):
    before = {t: list(v) for t, v in search_index.items()}
    submit_record(user, record_id, value, tag)
    fresh = {t: v for t, v in search_index.items() if before.get(t) != v}
    sock = socket.create_connection((host, port), timeout=10)
    payload = {"record_id": record_id,
               "envelope": records[record_id],
               "signer_key": get_signing_key(user)}
    payload["index"] = fresh
    send_frame(sock, payload)
    print("[client] server replied:", recv_frame(sock))
    sock.close()

def reset():
    for path in [record_file, key_file, log_file, "index.json", "he_key.json", "server_private.pem", "server_public.pem"]:
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            pass
    print("stored files removed")

if len(sys.argv) > 1 and sys.argv[1] == "reset":
    reset()
    sys.exit(0)

load_all()
index_key = hashlib.sha256((system_name + "-index").encode()).digest()[:key_bytes]
server_private, server_public = server_keys()
he_pub = he_keygen()
he_secret = he_pub.pop("secret")

if __name__ == "__main__":
    given = sys.argv[1:]
    if len(given) >= 4:
        run_client(given[0], given[1], given[2], given[3])
    else:
        print(system_name, "- client")
        who = input("User name: ").strip() or "alice"
        which = input("Ballot ID: ").strip() or "R001"
        amount = input("CandidateID (a number): ").strip() or "1"
        where = input("ConstituencyID: ").strip() or "101"
        run_client(who, which, amount, where)
