import os
import sys
import json
import hashlib
import socket
from datetime import datetime

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

try:
    sys.stdout.reconfigure(errors="replace")
except Exception:
    pass

system_name = "vote"
roles = {
    "voter": ["submit", "view_own"],
    "server": ["verify", "search", "view_all", "tamper_test"],
    "tally": ["aggregate", "threshold_decrypt"],
    "auditor": ["view_hashes", "audit"]
}
key_bytes = 32
rsa_bits = 4096
window_opens = "2000-01-01 00:00:00"
window_closes = "2099-12-31 23:59:59"
host, port = "127.0.0.1", 9099

records = {}
search_index = {}
signer_keys = {}
record_file = "records.json"
key_file = "keys.json"
log_file = "audit.log"

server_role = "server"

def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def decrypt_data(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), 16).decode(errors="replace")

def server_keys():
    if os.path.exists("server_private.pem"):
        key = RSA.import_key(open("server_private.pem", "rb").read())
    else:
        key = RSA.generate(rsa_bits)
        open("server_private.pem", "wb").write(key.export_key())
        open("server_public.pem", "wb").write(key.publickey().export_key())
    return key, key.publickey()

def unwrap_key(blob, private_key):
    return PKCS1_OAEP.new(private_key).decrypt(blob)

def hash_data(data):
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha512(data).hexdigest()

def hash_matches(data, stored_hex):
    return hash_data(data) == stored_hex

def verify_hash(digest_hex, signature, key):
    p, g, y = key["p"], key["g"], key["y"]
    r, s = int(signature[0]), int(signature[1])
    if not 0 < r < p:
        return False
    h = int(digest_hex, 16) % (p - 1)
    return pow(g, h, p) == (pow(y, r, p) * pow(r, s, p)) % p

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

def signer_public(user):
    return signer_keys[user]

def check_permission(subject, action):
    if action not in roles.get(subject, []):
        print("ACCESS DENIED:", subject, "cannot", action)
        log_action(subject, "DENIED " + action)
        return False
    return True

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

    try:
        sig_ok = verify_hash(row["hash"], row["signature"],
                             signer_public(row["user"]))
    except PermissionError as exc:
        print("Output: cannot verify -", exc)
        sig_ok = False
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
    print("Output:", record_id, row["status"] + "; encrypted candidateid left untouched")
    return accepted

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

if __name__ == "__main__":
    print(system_name, "- server. Ctrl+C to stop.")
    try:
        run_server()
    except KeyboardInterrupt:
        print("\nserver stopped")
