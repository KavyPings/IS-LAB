# ===== EDIT THIS SECTION - CONFIG START =====
CONFIG = {
    "system_name": "SecureSystem",
    "cipher":      "DES",
    "mode":        "ECB",
    "key":         "A1B2C3D4",
    "signature":   "RSA",
    "rsa_bits":    2048,
    "hash":        "sha256",
    "sign_target": "cipher",
    "db_file":     "records.json",
    "key_dir":     "keys",
    "log_file":    "audit.log",
}

ROLES = {
    "student": {"label": "Student", "permissions": ['upload', 'view_own']},
    "faculty": {"label": "Faculty", "permissions": ['decrypt_verify', 'view_all', 'tamper_test']},
    "hod": {"label": "HoD", "permissions": ['view_hashes', 'audit']},
}
# ===== CONFIG END =====

# ============================ CORE HELPERS ===================================
import os
import sys
import json
import math
import time
import hmac
import random
import string
import socket
import hashlib
import logging
import shutil
import threading
from datetime import datetime, timedelta

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def read_input(source, force_file=False):
    if isinstance(source, (bytes, bytearray)):
        return bytes(source)
    if force_file or (isinstance(source, str) and os.path.isfile(source)):
        with open(source, "rb") as f:
            return f.read()
    return str(source).encode()

def write_output(path, data):
    if isinstance(data, str):
        data = data.encode()
    with open(path, "wb") as f:
        f.write(data)
    return path

def ask_input(prompt="Enter text or filename: "):
    raw = input(prompt).strip()
    if os.path.isfile(raw):
        print("  [reading file:", raw + "]")
    return read_input(raw), raw

def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

try:
    sys.stdout.reconfigure(errors="replace")
except Exception:
    pass

def safe_text(data):
    if isinstance(data, bytes):
        try:
            data = data.decode("utf-8")
        except UnicodeDecodeError:
            return "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    enc = getattr(sys.stdout, "encoding", None) or "ascii"
    return str(data).encode(enc, "replace").decode(enc, "replace")

def hexs(value, group=0):
    if isinstance(value, bool):
        value = int(value)
    if isinstance(value, int):
        h = "%x" % abs(value)
        h = ("-" if value < 0 else "") + ("0" + h if len(h) % 2 else h)
    elif isinstance(value, (bytes, bytearray)):
        h = bytes(value).hex()
    elif isinstance(value, (list, tuple)):
        return ", ".join(hexs(v, group) for v in value)
    else:
        h = str(value).encode().hex()
    if group:
        h = " ".join(h[i:i + group] for i in range(0, len(h), group))
    return h

def unhexs(text):
    return int(str(text).replace(" ", ""), 16)

def show(label, value, width=18):
    print(str(label).ljust(width), ":", value)

def preview(data, n=64):
    s = data.hex() if isinstance(data, (bytes, bytearray)) else str(data)
    return s if len(s) <= n else s[:n] + "..."

def clean_text(text, merge_j=False):
    if isinstance(text, (bytes, bytearray)):
        text = text.decode(errors="ignore")
    t = "".join(c for c in str(text).upper() if c.isalpha())
    return t.replace("J", "I") if merge_j else t

def egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x, y = egcd(b, a % b)
    return g, y, x - (a // b) * y

def modinv(a, m):
    a %= m
    g, x, _ = egcd(a, m)
    return None if g != 1 else x % m

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def is_prime(n):
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True

def gen_prime(bits, cond=None):
    while True:
        p = random.getrandbits(bits) | 1 | (1 << (bits - 1))
        if is_prime(p) and (cond is None or cond(p)):
            return p

def make_key(key, size):
    if isinstance(key, (bytes, bytearray)):
        b = bytes(key)
    else:
        s = str(key)
        if len(s.encode()) == size:
            return s.encode()
        try:
            h = bytes.fromhex(s)
            if len(h) == size:
                return h
        except ValueError:
            pass
        b = s.encode()
    return b[:size] if len(b) >= size else b + b"\0" * (size - len(b))

# ===== DES / 3DES / AES-128/192/256  x  ECB CBC CFB OFB CTR GCM  (Lab 2) ====
from Crypto.Cipher import DES, DES3, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

SYM_ALGOS = {"DES": (DES, 8), "3DES": (DES3, 24), "AES-128": (AES, 16),
             "AES-192": (AES, 24), "AES-256": (AES, 32)}
BLOCK_MODES = ("ECB", "CBC")
STREAM_MODES = ("CFB", "OFB", "CTR")

def _fix_3des_key(k):
    try:
        return DES3.adjust_key_parity(k)
    except ValueError:
        cand = hashlib.sha256(k).digest()[:24]
        for _ in range(64):
            try:
                return DES3.adjust_key_parity(cand)
            except ValueError:
                cand = hashlib.sha256(cand).digest()[:24]
        raise

def _sym_setup(algo, key):
    mod, size = SYM_ALGOS[algo]
    k = make_key(key, size)
    return mod, (_fix_3des_key(k) if algo == "3DES" else k)

def _new_cipher(mod, k, mode, iv):
    if mode == "ECB":
        return mod.new(k, mod.MODE_ECB)
    if mode == "CBC":
        return mod.new(k, mod.MODE_CBC, iv)
    if mode == "CFB":
        return mod.new(k, mod.MODE_CFB, iv)
    if mode == "OFB":
        return mod.new(k, mod.MODE_OFB, iv)
    if mode == "CTR":
        return mod.new(k, mod.MODE_CTR, nonce=iv[:mod.block_size // 2])
    raise ValueError("mode: ECB CBC CFB OFB CTR (for GCM use aes_gcm_*)")

def sym_encrypt(data, key, algo="AES-256", mode="ECB", iv=None):
    data = read_input(data)
    mod, k = _sym_setup(algo, key)
    if mode != "ECB" and iv is None:
        iv = get_random_bytes(mod.block_size)
    c = _new_cipher(mod, k, mode, iv)
    payload = pad(data, mod.block_size) if mode in BLOCK_MODES else data
    return c.encrypt(payload), (None if mode == "ECB" else iv)

def sym_decrypt(ciphertext, key, algo="AES-256", mode="ECB", iv=None):
    mod, k = _sym_setup(algo, key)
    out = _new_cipher(mod, k, mode, iv).decrypt(ciphertext)
    return unpad(out, mod.block_size) if mode in BLOCK_MODES else out

def aes_gcm_encrypt(data, key, nonce=None):
    nonce = nonce or get_random_bytes(12)
    c = AES.new(make_key(key, 32), AES.MODE_GCM, nonce=nonce)
    ct, tag = c.encrypt_and_digest(read_input(data))
    return ct, nonce, tag

def aes_gcm_decrypt(ciphertext, key, nonce, tag):
    c = AES.new(make_key(key, 32), AES.MODE_GCM, nonce=nonce)
    return c.decrypt_and_verify(ciphertext, tag)

def encrypt_file(infile, outfile, key, algo="AES-256", mode="CBC"):
    ct, iv = sym_encrypt(read_input(infile, True), key, algo, mode)
    write_output(outfile, (iv or b"") + ct)
    return outfile

def decrypt_file(infile, outfile, key, algo="AES-256", mode="CBC"):
    mod, _ = _sym_setup(algo, key)
    blob = read_input(infile, True)
    iv, ct = (None, blob) if mode == "ECB" else \
        (blob[:mod.block_size], blob[mod.block_size:])
    pt = sym_decrypt(ct, key, algo, mode, iv)
    write_output(outfile, pt)
    return pt

def compare_symmetric(message="Performance Testing of Encryption Algorithms",
                      algos=("DES", "3DES", "AES-128", "AES-192", "AES-256"),
                      modes=("ECB", "CBC", "CFB", "OFB", "CTR"),
                      repeats=200, key="0123456789ABCDEF0123456789ABCDEF"):
    data = read_input(message)
    print("\n%-9s %-5s %13s %13s" % ("ALGO", "MODE", "ENC us", "DEC us"))
    print("-" * 44)
    res = []
    for a in algos:
        for m in modes:
            try:
                t0 = time.perf_counter()
                for _ in range(repeats):
                    ct, iv = sym_encrypt(data, key, a, m)
                e = (time.perf_counter() - t0) / repeats * 1e6
                t0 = time.perf_counter()
                for _ in range(repeats):
                    sym_decrypt(ct, key, a, m, iv)
                d = (time.perf_counter() - t0) / repeats * 1e6
                print("%-9s %-5s %13.2f %13.2f" % (a, m, e, d))
                res.append((a, m, e, d))
            except Exception as ex:
                print("%-9s %-5s skipped (%s)" % (a, m, ex))
    return res

# ================ RSA: textbook + 2048-bit + hybrid  (Lab 3) ================
from Crypto.PublicKey import RSA as _RSA
from Crypto.Cipher import PKCS1_OAEP

def rsa_keygen_textbook(p=61, q=53, e=17, bits=None):
    if bits:
        p = gen_prime(bits)
        q = gen_prime(bits)
        while q == p:
            q = gen_prime(bits)
    n, phi = p * q, (p - 1) * (q - 1)
    if gcd(e, phi) != 1:
        e = next(c for c in (65537, 17, 5, 3) if gcd(c, phi) == 1)
    return (n, e), (n, modinv(e, phi)), {"p": p, "q": q, "phi": phi}

def rsa_encrypt_textbook(message, public):
    n, e = public
    if n <= 255:
        raise ValueError("n must be > 255 for byte-wise RSA")
    return [pow(b, e, n) for b in read_input(message)]

def rsa_decrypt_textbook(cipher_list, private):
    n, d = private
    return bytes(pow(c, d, n) for c in cipher_list)

def rsa_generate(bits=2048):
    k = _RSA.generate(bits)
    return k, k.publickey()

def rsa_save(key, path):
    return write_output(path, key.export_key())

def rsa_load(path):
    with open(path, "rb") as f:
        return _RSA.import_key(f.read())

def rsa_encrypt(data, public_key):
    return PKCS1_OAEP.new(public_key).encrypt(read_input(data))

def rsa_decrypt(ciphertext, private_key):
    return PKCS1_OAEP.new(private_key).decrypt(ciphertext)

def rsa_hybrid_encrypt(data, public_key):
    session = get_random_bytes(32)
    ct, nonce, tag = aes_gcm_encrypt(read_input(data), session)
    return rsa_encrypt(session, public_key), nonce, tag, ct

def rsa_hybrid_decrypt(enc_key, nonce, tag, ciphertext, private_key):
    session = rsa_decrypt(enc_key, private_key)
    return aes_gcm_decrypt(ciphertext, session, nonce, tag)

# ========================= HASHING  (Lab 5) =================================
def custom_hash(data):
    seq = data if isinstance(data, (bytes, bytearray)) else str(data).encode()
    h = 5381
    for b in seq:
        h = h * 33 + b
        h ^= (h >> 16)
    return h & 0xFFFFFFFF

def hash_data(data, algo="sha256"):
    data = read_input(data)
    if algo == "custom":
        return format(custom_hash(data), "08x")
    return hashlib.new(algo, data).hexdigest()

def hash_file(path, algo="sha256", chunk=65536):
    if algo == "custom":
        return format(custom_hash(read_input(path, True)), "08x")
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        while True:
            blk = f.read(chunk)
            if not blk:
                break
            h.update(blk)
    return h.hexdigest()

def verify_hash(data, expected, algo="sha256"):
    return hmac.compare_digest(hash_data(data, algo), expected)

def hmac_digest(data, key, algo="sha256"):
    k = key.encode() if isinstance(key, str) else key
    return hmac.new(k, read_input(data), getattr(hashlib, algo)).hexdigest()

def hmac_verify(data, key, expected, algo="sha256"):
    return hmac.compare_digest(hmac_digest(data, key, algo), expected)

def avalanche_demo(text="Information Security", algo="sha256"):
    a = bytearray(read_input(text))
    b = bytearray(a)
    b[0] ^= 1
    ha, hb = hash_data(bytes(a), algo), hash_data(bytes(b), algo)
    show("original", ha)
    show("1 bit changed", hb)
    show("chars differing", "%d / %d" % (sum(x != y for x, y in zip(ha, hb)),
                                         len(ha)))
    return ha, hb

def compare_hashes(count=100, length=20,
                   algos=("md5", "sha1", "sha256", "sha512", "custom")):
    data = ["".join(random.choices(string.ascii_letters + string.digits,
                                   k=length)) for _ in range(count)]
    print("\ndataset: %d random strings of length %d" % (count, length))
    print("%-8s %12s %10s %12s" % ("ALGO", "TIME s", "BITS", "COLLISIONS"))
    print("-" * 46)
    out = []
    for a in algos:
        t0 = time.perf_counter()
        d = [hash_data(s, a) for s in data]
        el = time.perf_counter() - t0
        col = len(d) - len(set(d))
        print("%-8s %12.6f %10d %12d" % (a, el, len(d[0]) * 4, col))
        out.append((a, el, col))
    print("(full digests never collide on a set this small - the space is")
    print(" astronomically large. Truncate them to SEE the birthday effect:)")
    collisions_truncated(data, algos)
    return out

def collisions_truncated(data=None, algos=("md5", "sha1", "sha256"),
                         bits=(16, 20, 24, 32), count=2000):
    if data is None:
        data = ["".join(random.choices(string.ascii_letters + string.digits,
                                       k=12)) for _ in range(count)]
    print("\ntruncated-digest collisions over %d strings" % len(data))
    print("%-8s" % "ALGO" + "".join("%10s" % ("%d bit" % b) for b in bits))
    print("-" * (8 + 10 * len(bits)))
    table = {}
    for a in algos:
        row = []
        for b in bits:
            chars = b // 4
            seen, col = {}, 0
            for s in data:
                dg = hash_data(s, a)[:chars]
                if dg in seen and seen[dg] != s:
                    col += 1
                seen[dg] = s
            row.append(col)
        table[a] = row
        print("%-8s" % a + "".join("%10d" % v for v in row))
    return table

# ================== DIGITAL SIGNATURES  (Lab 6) =============================
from Crypto.Signature import pkcs1_15, pss
from Crypto.Hash import SHA256 as _CSHA256, SHA512 as _CSHA512
from Crypto.Hash import MD5 as _CMD5, SHA1 as _CSHA1

_PYCRYPTO_HASH = {"sha256": _CSHA256, "sha512": _CSHA512,
                  "md5": _CMD5, "sha1": _CSHA1}

def rsa_sign(data, private_key, scheme="pkcs1v15", algo="sha256"):
    h = _PYCRYPTO_HASH.get(algo, _CSHA256).new(read_input(data))
    signer = pss.new(private_key) if scheme == "pss" else \
        pkcs1_15.new(private_key)
    return signer.sign(h)

def rsa_verify(data, signature, public_key, scheme="pkcs1v15", algo="sha256"):
    h = _PYCRYPTO_HASH.get(algo, _CSHA256).new(read_input(data))
    v = pss.new(public_key) if scheme == "pss" else pkcs1_15.new(public_key)
    try:
        v.verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

def ecdsa_sign(data, private_key):
    return private_key.sign(read_input(data), ec.ECDSA(_chashes.SHA256()))

def ecdsa_verify(data, signature, public_key):
    try:
        public_key.verify(signature, read_input(data),
                          ec.ECDSA(_chashes.SHA256()))
        return True
    except Exception:
        return False

def elgamal_sign(data, public, x):
    p, g, y = public
    h = int(hashlib.sha256(read_input(data)).hexdigest(), 16) % (p - 1)
    while True:
        k = random.randint(2, p - 2)
        if gcd(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    s = ((h - x * r) * modinv(k, p - 1)) % (p - 1)
    return elgamal_sign(data, public, x) if s == 0 else (r, s)

def sig_hex(signature):
    if isinstance(signature, (tuple, list)):
        return "r=%s s=%s" % (hexs(signature[0]), hexs(signature[1]))
    if isinstance(signature, (bytes, bytearray)):
        return hexs(signature)
    return str(signature)

def elgamal_verify(data, signature, public):
    p, g, y = public
    r, s = signature
    if not 0 < r < p:
        return False
    h = int(hashlib.sha256(read_input(data)).hexdigest(), 16) % (p - 1)
    return (pow(y, r, p) * pow(r, s, p)) % p == pow(g, h, p)

SCHNORR_P, SCHNORR_Q, SCHNORR_G = 467, 233, 4

def schnorr_keygen(p=SCHNORR_P, q=SCHNORR_Q, g=SCHNORR_G):
    x = random.randint(1, q - 1)
    return (p, q, g, pow(g, x, p)), x

def _schnorr_e(data, r, q):
    return int(hashlib.sha256(read_input(data) + str(r).encode()).hexdigest(),
               16) % q

def schnorr_sign(data, public, x):
    p, q, g, y = public
    k = random.randint(1, q - 1)
    r = pow(g, k, p)
    e = _schnorr_e(data, r, q)
    return e, (k + x * e) % q

def schnorr_verify(data, signature, public):
    p, q, g, y = public
    e, s = signature
    rv = (pow(g, s, p) * modinv(pow(y, e, p), p)) % p
    return _schnorr_e(data, rv, q) == e

def secure_send(data, sender_priv, sym_key, algo="AES-256", mode="CBC"):
    ct, iv = sym_encrypt(read_input(data), sym_key, algo, mode)
    return {"ciphertext": ct.hex(), "iv": iv.hex() if iv else None,
            "hash": hashlib.sha256(ct).hexdigest(),
            "signature": rsa_sign(ct, sender_priv).hex(),
            "algo": algo, "mode": mode, "time": timestamp()}

def secure_receive(packet, sender_pub, sym_key):
    ct = bytes.fromhex(packet["ciphertext"])
    iv = bytes.fromhex(packet["iv"]) if packet["iv"] else None
    rep = {"signature_valid": rsa_verify(ct, bytes.fromhex(
               packet["signature"]), sender_pub),
           "hash_match": hashlib.sha256(ct).hexdigest() == packet["hash"],
           "checked_at": timestamp()}
    pt = None
    if rep["signature_valid"] and rep["hash_match"]:
        pt = sym_decrypt(ct, sym_key, packet["algo"], packet["mode"], iv)
    return pt, rep

def format_hex_sig(data):
    return " ".join("0x%02x" % b for b in data)

def parse_hex_sig(text):
    return bytes(int(t, 16) for t in text.split())

def rsa_sign_raw(text, n, d):
    m = int.from_bytes(text.encode() if isinstance(text, str) else text, "big")
    return pow(m, d, n)

def rsa_verify_raw(signature_int, n, e):
    v = pow(signature_int, e, n)
    return v, v.to_bytes((v.bit_length() + 7) // 8 or 1, "big")

def rsa_raw_demo(text="Alice", bits=1024):
    priv, _pub = rsa_generate(bits)
    n, e, d = priv.n, priv.e, priv.d
    sig = rsa_sign_raw(text, n, d)
    blob = sig.to_bytes((n.bit_length() + 7) // 8, "big")
    show("text", text)
    show("signature", preview(format_hex_sig(blob), 60))
    _, back = rsa_verify_raw(int.from_bytes(parse_hex_sig(
        format_hex_sig(blob)), "big"), n, e)
    show("s^e mod n", back.decode(errors="replace"))
    print("note: raw RSA is malleable - sig(a)*sig(b) = sig(a*b).")
    print("      Always hash first and pad (pkcs1v15 / pss) for real use.")
    return sig

# ============= ACCESS CONTROL MODELS  (Lab 4) ===============================
class RBAC:

    def __init__(self, roles=None):
        self.roles = roles or {}
        self.users = {}

    def add_role(self, role, permissions):
        self.roles[role] = list(permissions)

    def assign(self, user, role):
        self.users.setdefault(user, set()).add(role)

    def allowed(self, who, permission):
        if who in self.roles:
            return permission in self.roles[who]
        return any(permission in self.roles.get(r, [])
                   for r in self.users.get(who, []))

    def require(self, role, permission):
        if not self.allowed(role, permission):
            raise PermissionError("role '%s' may not '%s'" % (role, permission))
        return True

    def menu_for(self, role):
        return self.roles.get(role, [])

def abac_allowed(user_attrs, object_attrs, env_attrs, policy):
    return bool(policy(user_attrs, object_attrs, env_attrs))

LEVELS = {"PUBLIC": 0, "CONFIDENTIAL": 1, "SECRET": 2, "TOPSECRET": 3}

def bell_lapadula(subject_level, object_level, action):
    s, o = LEVELS[subject_level.upper()], LEVELS[object_level.upper()]
    if action == "read":
        return s >= o
    if action == "write":
        return s <= o
    return False

def mac_allowed(clearance, classification, policy_ok=True):
    return LEVELS[clearance.upper()] >= LEVELS[classification.upper()] \
        and policy_ok

class DAC:

    def __init__(self):
        self.matrix = {}

    def grant(self, subject, obj, *rights):
        self.matrix.setdefault(subject, {}).setdefault(obj, set()).update(rights)

    def revoke(self, subject, obj, *rights):
        if subject in self.matrix and obj in self.matrix[subject]:
            self.matrix[subject][obj] -= set(rights)

    def allowed(self, subject, obj, right):
        return right in self.matrix.get(subject, {}).get(obj, set())

def time_allowed(start="09:00", end="17:00", now=None):
    return start <= (now or datetime.now().strftime("%H:%M")) <= end

class TimedGrant:

    def __init__(self):
        self.grants = {}

    def grant(self, user, resource, minutes=60):
        self.grants[(user, resource)] = datetime.now() + timedelta(
            minutes=minutes)

    def revoke(self, user, resource):
        self.grants.pop((user, resource), None)

    def allowed(self, user, resource):
        exp = self.grants.get((user, resource))
        return exp is not None and datetime.now() < exp

# ===========================================================================
# ===========================================================================
CLASSICAL_CIPHERS = {"ADDITIVE", "MULTIPLICATIVE", "AFFINE", "VIGENERE",
                     "AUTOKEY", "PLAYFAIR", "HILL", "TRANSPOSITION"}
MODERN_CIPHERS = {"DES", "3DES", "AES-128", "AES-192", "AES-256"}

KEY_HELP = {
    "ADDITIVE":       "int, e.g. 20",
    "MULTIPLICATIVE": "int coprime with 26, e.g. 15",
    "AFFINE":         "'a,b' or (a, b), e.g. '15,20'",
    "VIGENERE":       "keyword, e.g. 'dollars'",
    "AUTOKEY":        "int seed e.g. 7, or keyword e.g. 'HEALTH'",
    "PLAYFAIR":       "keyword, e.g. 'GUIDANCE'",
    "HILL":           "'3,3;2,7' or [[3,3],[2,7]]",
    "TRANSPOSITION":  "'3142' or a word like 'SECRET'",
    "DES":            "8 chars, e.g. 'A1B2C3D4'",
    "3DES":           "24 bytes / 48 hex chars",
    "AES-128":        "16 bytes / 32 hex chars",
    "AES-192":        "24 bytes / 48 hex chars",
    "AES-256":        "32 bytes / 64 hex chars",
}

def parse_cipher_key(cipher, key):
    c = cipher.upper()
    if c == "AFFINE":
        if isinstance(key, (tuple, list)):
            return int(key[0]), int(key[1])
        a, b = str(key).replace("(", "").replace(")", "").split(",")
        return int(a), int(b)
    if c == "HILL":
        if isinstance(key, (list, tuple)):
            return [list(map(int, row)) for row in key]
        return [[int(v) for v in row.split(",")]
                for row in str(key).split(";")]
    if c in ("ADDITIVE", "MULTIPLICATIVE"):
        return int(key)
    return key

def encrypt_any(data, cfg):
    c = cfg["cipher"].upper()
    key = parse_cipher_key(c, cfg["key"])
    if c in CLASSICAL_CIPHERS:
        text = read_input(data).decode(errors="ignore")
        if c == "ADDITIVE":
            out = additive_encrypt(text, key)
        elif c == "MULTIPLICATIVE":
            out = multiplicative_encrypt(text, key)
        elif c == "AFFINE":
            out = affine_encrypt(text, key[0], key[1])
        elif c == "VIGENERE":
            out = vigenere_encrypt(text, key)
        elif c == "AUTOKEY":
            out = autokey_encrypt(text, key)
        elif c == "PLAYFAIR":
            out = playfair_encrypt(text, key)
        elif c == "HILL":
            out = hill_encrypt(text, key)
        else:
            out = transposition_encrypt(text, key)
        return out.encode(), None
    return sym_encrypt(data, key, c, cfg.get("mode", "ECB"))

def decrypt_any(ciphertext, iv, cfg):
    c = cfg["cipher"].upper()
    key = parse_cipher_key(c, cfg["key"])
    if c in CLASSICAL_CIPHERS:
        text = ciphertext.decode(errors="ignore")
        if c == "ADDITIVE":
            out = additive_decrypt(text, key)
        elif c == "MULTIPLICATIVE":
            out = multiplicative_decrypt(text, key)
        elif c == "AFFINE":
            out = affine_decrypt(text, key[0], key[1])
        elif c == "VIGENERE":
            out = vigenere_decrypt(text, key)
        elif c == "AUTOKEY":
            out = autokey_decrypt(text, key)
        elif c == "PLAYFAIR":
            out = playfair_decrypt(text, key)
        elif c == "HILL":
            out = hill_decrypt(text, key)
        else:
            out = transposition_decrypt(text, key)
        return out.encode()
    return sym_decrypt(ciphertext, key, c, cfg.get("mode", "ECB"), iv)

def display_cipher(ciphertext, cfg):
    if cfg["cipher"].upper() in CLASSICAL_CIPHERS:
        return safe_text(ciphertext)
    return ciphertext.hex()

def cipher_note(cfg):
    if cfg["cipher"].upper() in CLASSICAL_CIPHERS:
        return ("classical cipher: A-Z only, so spaces, digits and "
                "punctuation are dropped by design")
    return "block cipher: any byte content is preserved exactly"

def sig_keygen(scheme, rsa_bits=2048):
    s = scheme.upper()
    if s == "RSA":
        return rsa_generate(rsa_bits)
    if s == "ECDSA":
        return ecc_keygen()
    if s == "ELGAMAL":
        pub, x = elgamal_keygen()
        return x, pub
    if s == "SCHNORR":
        pub, x = schnorr_keygen()
        return x, pub
    raise ValueError("signature: RSA / ECDSA / ELGAMAL / SCHNORR")

def sig_sign(data, priv, pub, scheme, algo="sha256"):
    s = scheme.upper()
    if s == "RSA":
        return rsa_sign(data, priv, algo=algo).hex()
    if s == "ECDSA":
        return ecdsa_sign(data, priv).hex()
    if s == "ELGAMAL":
        return json.dumps(elgamal_sign(data, pub, priv))
    return json.dumps(schnorr_sign(data, pub, priv))

def sig_verify(data, signature, pub, scheme, algo="sha256"):
    s = scheme.upper()
    try:
        if s == "RSA":
            return rsa_verify(data, bytes.fromhex(signature), pub, algo=algo)
        if s == "ECDSA":
            return ecdsa_verify(data, bytes.fromhex(signature), pub)
        sig = tuple(json.loads(signature))
        if s == "ELGAMAL":
            return elgamal_verify(data, sig, pub)
        return schnorr_verify(data, sig, pub)
    except Exception:
        return False

def sig_serialize(scheme, priv, pub):
    s = scheme.upper()
    if s == "RSA":
        return {"scheme": s, "private": priv.export_key().decode(),
                "public": pub.export_key().decode()}
    if s == "ECDSA":
        return {"scheme": s,
                "private": priv.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption()).decode(),
                "public": pub.public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo).decode()}
    return {"scheme": s, "private": priv, "public": list(pub)}

def sig_deserialize(rec):
    s = rec["scheme"].upper()
    if s == "RSA":
        return _RSA.import_key(rec["private"]), _RSA.import_key(rec["public"])
    if s == "ECDSA":
        return (serialization.load_pem_private_key(rec["private"].encode(),
                                                   password=None),
                serialization.load_pem_public_key(rec["public"].encode()))
    return rec["private"], tuple(rec["public"])

# ===========================================================================
# ===========================================================================
if "CONFIG" not in globals():
    CONFIG = {
        "system_name": "EduSecure",
        "cipher":      "DES",
        "mode":        "ECB",
        "key":         "A1B2C3D4",
        "signature":   "RSA",
        "rsa_bits":    2048,
        "hash":        "sha256",
        "sign_target": "cipher",
        "db_file":     "records.json",
        "key_dir":     "keys",
        "log_file":    "audit.log",
    }

if "ROLES" not in globals():
    ROLES = {
        "student": {"label": "Student",
                    "permissions": ["upload", "view_own"]},
        "faculty": {"label": "Faculty",
                    "permissions": ["decrypt_verify", "view_all",
                                    "tamper_test"]},
        "hod":     {"label": "HoD",
                    "permissions": ["view_hashes", "audit"]},
    }

ACTIONS = {
    "upload":         ("Upload a record (encrypt + hash + sign)",
                       "action_upload"),
    "view_own":       ("View my records (encrypted + hashed forms)",
                       "action_view_own"),
    "decrypt_verify": ("Decrypt, verify signature, check integrity",
                       "action_decrypt_verify"),
    "view_all":       ("List all stored records", "action_view_all"),
    "view_hashes":    ("View hashes only + verify signatures",
                       "action_view_hashes"),
    "tamper_test":    ("Tamper test (corrupt a record, then re-verify)",
                       "action_tamper_test"),
    "audit":          ("View audit log", "action_audit"),
}

class SecureSystem:

    def __init__(self, config=None, roles=None):
        self.cfg = dict(CONFIG)
        self.cfg.update(config or {})
        self.roles = roles or ROLES
        os.makedirs(self.cfg["key_dir"], exist_ok=True)
        self.records = self._load(self.cfg["db_file"], [])
        self.keystore = self._load(
            os.path.join(self.cfg["key_dir"], "keystore.json"), {})

    @staticmethod
    def _load(path, default):
        if os.path.exists(path):
            try:
                with open(path) as f:
                    return json.load(f)
            except Exception:
                return default
        return default

    def _save(self):
        with open(self.cfg["db_file"], "w") as f:
            json.dump(self.records, f, indent=2)
        with open(os.path.join(self.cfg["key_dir"], "keystore.json"), "w") as f:
            json.dump(self.keystore, f, indent=2)

    def _log(self, text):
        with open(self.cfg["log_file"], "a") as f:
            f.write("%s - %s\n" % (timestamp(), text))

    def _keys(self, user):
        scheme = self.cfg["signature"].upper()
        rec = self.keystore.get(user)
        if rec and rec.get("scheme") == scheme:
            return sig_deserialize(rec)
        priv, pub = sig_keygen(scheme, self.cfg["rsa_bits"])
        self.keystore[user] = sig_serialize(scheme, priv, pub)
        self._save()
        self._log("KEY GENERATED (%s) - %s" % (scheme, user))
        print("  [generated %s key pair for %s]" % (scheme, user))
        return priv, pub

    def allowed(self, role, permission):
        return permission in self.roles.get(role, {}).get("permissions", [])

    def require(self, role, permission):
        if not self.allowed(role, permission):
            raise PermissionError("role '%s' may not '%s'" % (role, permission))
        return True

    def upload(self, owner, data, filename="record.txt", verbose=True):
        plain = read_input(data)
        ct, iv = encrypt_any(plain, self.cfg)
        target = ct if self.cfg["sign_target"] == "cipher" else plain
        digest = hash_data(target, self.cfg["hash"])
        priv, pub = self._keys(owner)
        signature = sig_sign(target, priv, pub, self.cfg["signature"])

        rec = {"id": len(self.records) + 1, "owner": owner,
               "filename": filename, "cipher": self.cfg["cipher"],
               "mode": self.cfg["mode"], "ciphertext": ct.hex(),
               "iv": iv.hex() if iv else None, "hash": digest,
               "hash_algo": self.cfg["hash"], "signature": signature,
               "sig_scheme": self.cfg["signature"],
               "sign_target": self.cfg["sign_target"],
               "uploaded": timestamp(), "verifications": []}
        self.records.append(rec)
        self._save()
        self._log("UPLOAD - %s - record #%d" % (owner, rec["id"]))

        if verbose:
            print("\n--- record uploaded ---")
            show("owner", owner, 22)
            show("cipher (%s/%s)" % (rec["cipher"], rec["mode"]),
                 preview(display_cipher(ct, self.cfg)), 22)
            show("%s hash" % rec["hash_algo"], preview(digest, 70), 22)
            show("%s signature" % rec["sig_scheme"],
                 preview(sig_hex(signature), 48), 22)
            show("timestamp", rec["uploaded"], 22)
        return rec

    def verify_record(self, rec_id, verbose=True):
        rec = next((r for r in self.records if r["id"] == rec_id), None)
        if not rec:
            print("no such record:", rec_id)
            return None, None
        ct = bytes.fromhex(rec["ciphertext"])
        iv = bytes.fromhex(rec["iv"]) if rec["iv"] else None

        plaintext, err = None, None
        try:
            plaintext = decrypt_any(ct, iv, self.cfg)
        except Exception as ex:
            err = str(ex)

        target = ct if rec["sign_target"] == "cipher" else (plaintext or b"")
        recomputed = hash_data(target, rec["hash_algo"])
        hash_ok = recomputed == rec["hash"]
        _, pub = self._keys(rec["owner"])
        sig_ok = sig_verify(target, rec["signature"], pub, rec["sig_scheme"])

        result = {"signature_valid": sig_ok, "integrity_ok": hash_ok,
                  "decrypted": err is None, "checked_at": timestamp()}
        rec["verifications"].append(result)
        self._save()
        self._log("VERIFY - record #%d - sig=%s hash=%s"
                  % (rec_id, sig_ok, hash_ok))

        if verbose:
            print("\n--- verification of record #%d ---" % rec_id)
            show("owner", rec["owner"])
            show("decrypted", safe_text(plaintext)
                 if plaintext is not None else "FAILED (%s)" % err)
            show("stored hash", preview(rec["hash"], 70))
            show("recomputed", preview(recomputed, 70))
            show("integrity", "OK" if hash_ok else "FAILED")
            show("signature", "VALID" if sig_ok else "INVALID")
            show("checked at", result["checked_at"])
        return plaintext, result

    def tamper(self, rec_id, verbose=True):
        rec = next((r for r in self.records if r["id"] == rec_id), None)
        if not rec:
            return None
        ct = bytearray(bytes.fromhex(rec["ciphertext"]))
        if self.cfg["cipher"].upper() in CLASSICAL_CIPHERS:
            ct[0] = ord("A") + (ct[0] - ord("A") + 1) % 26
        else:
            ct[0] ^= 0xFF
        rec["ciphertext"] = bytes(ct).hex()
        self._save()
        self._log("TAMPER SIMULATED - record #%d" % rec_id)
        if verbose:
            print("\n[!] record #%d deliberately corrupted" % rec_id)
        return rec

    def action_upload(self, user):
        raw = input("Record text or filename: ").strip()
        if os.path.isfile(raw):
            data, name = read_input(raw), raw
            print("  [read %d bytes from file: %s]" % (len(data), raw))
        else:
            data, name = raw.encode(), "typed_record.txt"
            if raw.lower().endswith((".txt", ".dat", ".csv", ".json", ".pdf")):
                print("  [!] '%s' is not in this folder - treating it as "
                      "TYPED TEXT." % raw)
                print("      Create it first, or give the full path.")
            else:
                print("  [using typed text, %d characters]" % len(raw))
        self.upload(user, data, name)

    def action_view_own(self, user):
        mine = [r for r in self.records if r["owner"] == user]
        if not mine:
            print("no records for", user)
            return
        for r in mine:
            print("\n#%d  %s  (%s)" % (r["id"], r["filename"], r["uploaded"]))
            show("  cipher", preview(display_cipher(
                bytes.fromhex(r["ciphertext"]), self.cfg)), 18)
            show("  hash", preview(r["hash"], 70), 18)

    def action_view_all(self, user):
        if not self.records:
            print("no records stored")
            return
        print("\n%-4s %-12s %-20s %-20s %s"
              % ("ID", "OWNER", "FILE", "UPLOADED", "LAST CHECK"))
        print("-" * 76)
        for r in self.records:
            last = r["verifications"][-1] if r["verifications"] else None
            state = "-" if not last else ("OK" if last["signature_valid"]
                                          and last["integrity_ok"] else "FAILED")
            print("%-4d %-12s %-20s %-20s %s"
                  % (r["id"], r["owner"], r["filename"][:20],
                     r["uploaded"], state))

    def action_decrypt_verify(self, user):
        self.action_view_all(user)
        try:
            self.verify_record(int(input("Record id: ")))
        except ValueError:
            print("invalid id")

    def action_view_hashes(self, user):
        if not self.records:
            print("no records stored")
            return
        for r in self.records:
            target = bytes.fromhex(r["ciphertext"])
            _, pub = self._keys(r["owner"])
            ok = sig_verify(target, r["signature"], pub, r["sig_scheme"]) \
                if r["sign_target"] == "cipher" else "n/a (signed plaintext)"
            print("\n#%d  owner=%s  uploaded=%s"
                  % (r["id"], r["owner"], r["uploaded"]))
            show("  %s hash" % r["hash_algo"], preview(r["hash"], 70), 18)
            show("  signature", ok, 18)

    def action_tamper_test(self, user):
        self.action_view_all(user)
        try:
            rid = int(input("Record id to corrupt: "))
        except ValueError:
            return
        self.tamper(rid)
        self.verify_record(rid)

    def action_audit(self, user):
        print("\n--- audit log ---")
        try:
            with open(self.cfg["log_file"]) as f:
                for ln in f.readlines()[-25:]:
                    print("  ", ln.rstrip())
        except FileNotFoundError:
            print("   (empty)")

    def menu(self):
        name = self.cfg["system_name"]
        print("\n" + "=" * (len(name) + 24))
        print("   %s - Secure System" % name)
        print("=" * (len(name) + 24))
        show("cipher", "%s / %s" % (self.cfg["cipher"], self.cfg["mode"]), 12)
        show("signature", self.cfg["signature"], 12)
        show("hash", self.cfg["hash"], 12)
        print("note:", cipher_note(self.cfg))

        while True:
            print("\nLogin as:")
            keys = list(self.roles)
            for i, r in enumerate(keys, 1):
                print(" %d - %s" % (i, self.roles[r]["label"]))
            print(" 0 - Exit")
            ch = input("Select role: ").strip()
            if ch == "0":
                print("Goodbye.")
                return
            if not (ch.isdigit() and 1 <= int(ch) <= len(keys)):
                print("invalid choice")
                continue
            role = keys[int(ch) - 1]
            user = input("Username/ID: ").strip() or role
            self._role_menu(role, user)

    def _role_menu(self, role, user):
        perms = self.roles[role]["permissions"]
        while True:
            print("\n===== %s MENU (%s) ====="
                  % (self.roles[role]["label"].upper(), user))
            for i, p in enumerate(perms, 1):
                print(" %d - %s" % (i, ACTIONS[p][0]))
            print(" 0 - Logout")
            ch = input("Choice: ").strip()
            if ch == "0":
                return
            if not (ch.isdigit() and 1 <= int(ch) <= len(perms)):
                print("invalid choice")
                continue
            perm = perms[int(ch) - 1]
            try:
                self.require(role, perm)
                getattr(self, ACTIONS[perm][1])(user)
            except PermissionError as ex:
                print("ACCESS DENIED:", ex)
            except Exception as ex:
                print("error:", ex)

    def demo(self, owner="S001", text="Semester 5 marks DBMS 9 CN 8 OS 10"):
        print("\n" + "#" * 64)
        print("#  %s : %s/%s + %s + %s"
              % (self.cfg["system_name"], self.cfg["cipher"],
                 self.cfg["mode"], self.cfg["signature"], self.cfg["hash"]))
        print("#  %s" % cipher_note(self.cfg))
        print("#" * 64)
        rec = self.upload(owner, text, "ISL-5CCE-A2.txt")
        self.verify_record(rec["id"])
        print("\n[HoD view - hashes only]")
        self.action_view_hashes("hod")
        self.tamper(rec["id"])
        self.verify_record(rec["id"])
        print("\n>> integrity AND signature both fail after tampering -")
        print(">> exactly what they exist to detect.")
        return rec

def slurp(path, encoding="utf-8"):
    with open(path, encoding=encoding) as f:
        return f.read()

def count_lines(path):
    with open(path, encoding="utf-8") as f:
        return sum(1 for _ in f)

def tidy(*paths):
    import shutil
    for path in paths:
        try:
            if os.path.isdir(path):
                shutil.rmtree(path, ignore_errors=True)
            elif os.path.exists(path):
                os.remove(path)
        except OSError:
            pass

def reset_demo_files(cfg=None):
    import shutil
    cfg = cfg or CONFIG
    for p in (cfg["db_file"], cfg["log_file"]):
        try:
            if os.path.exists(p):
                os.remove(p)
        except OSError:
            pass
    shutil.rmtree(cfg["key_dir"], ignore_errors=True)

# ============================ RUN =========================
if __name__ == '__main__':
    import sys
    _arg = sys.argv[1] if len(sys.argv) > 1 else ''
    if _arg == 'reset':
        reset_demo_files()
    elif _arg == 'demo':
        reset_demo_files()
        SecureSystem().demo()
    else:
        SecureSystem().menu()
