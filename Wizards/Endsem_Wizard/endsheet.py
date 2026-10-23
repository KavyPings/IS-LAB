#!/usr/bin/env python3
r"""
================================================================================
 endsheet.py - END-SEM answer writer for the Information Security Lab (ICT 3141)
 Syllabus covered: Lab 1 - Lab 8
================================================================================

WHAT IT DOES
  You answer a few questions about the exam question in front of you.
  endsheet.py writes a complete, menu-driven, runnable answer file:

      answer.py         the answer with comments  (read this, understand it)
      answer_clean.py   the same answer, comments stripped (show this as output)

  The generated answer always covers the five marked components of an end-sem
  scenario question:

      Client-Server  client builds the record, server processes it (and a real
                     TCP client/server if you ask for it)
      ED             symmetric encryption + public-key key wrapping
      DSS            digital signature: sign and verify
      Hash           hashing and integrity verification
      Search         searchable encryption index (SSE or PKSE)

  plus whatever else the question adds: partial homomorphic encryption and
  encrypted aggregation (Lab 7), threshold decryption, trusted timestamps and
  deadline checks, role-based access control, and file-backed storage.

FIRST TIME SETUP
  python -m venv .venv
  .venv\Scripts\activate                 (Windows)
  source .venv/bin/activate              (macOS / Linux)
  pip install pycryptodome
  python endsheet.py --check

NORMAL EXAM USE
  python endsheet.py --wizard            answer the questions, get answer.py
  python answer.py demo                  full run, no typing, every output
  python answer.py                       the interactive menu (this is marked)

OTHER COMMANDS
  python endsheet.py --check             is the environment ready
  python endsheet.py --presets           list the ready-made scenarios
  python endsheet.py --build evoting     build a preset without the questions
  python endsheet.py --selftest          build and run many combinations
  python endsheet.py --options           every value each setting accepts

IF THE WIZARD IS NOT WHAT THE QUESTION WANTS
  Build the closest preset anyway, then edit the SETTINGS block at the top of
  answer.py, or paste the function you need out of
  IS_Lab_Codebase/Concepts/ALL_CONCEPTS_TOOLKIT.py.
================================================================================
"""

import ast
import io
import json
import os
import re
import subprocess
import sys
import tokenize
from datetime import datetime

# ---------------------------------------------------------------------------
# WHAT EVERY SETTING CAN BE
# ---------------------------------------------------------------------------

# name -> (pycryptodome class, key length in bytes, block size in bytes)
CIPHER_INFO = {
    "AES-128": ("AES", 16, 16),
    "AES-192": ("AES", 24, 16),
    "AES-256": ("AES", 32, 16),
    "DES": ("DES", 8, 8),
    "3DES": ("DES3", 24, 8),
}

MODES = ["CBC", "ECB", "CFB", "OFB", "CTR"]

# name -> (hashlib call, digest length in hex characters)
HASH_INFO = {
    "sha512": ("hashlib.sha512", 128),
    "sha256": ("hashlib.sha256", 64),
    "sha1": ("hashlib.sha1", 40),
    "md5": ("hashlib.md5", 32),
}

SIGNS = ["ELGAMAL", "RSA", "DSA", "ECDSA", "SCHNORR"]
WRAPS = ["RSA", "ECC", "NONE"]
HES = ["PAILLIER", "RSA_MUL", "ELGAMAL_MUL", "NONE"]
SEARCHES = ["SSE", "PKSE", "NONE"]

DEFAULTS = {
    "system_name": "SecureSystem",
    "record_word": "record",
    "tag_word": "department",
    "value_word": "amount",
    "cipher": "AES-256",
    "mode": "CBC",
    "wrap": "RSA",
    "rsa_bits": 2048,
    "hash": "sha512",
    "sign": "ELGAMAL",
    "he": "PAILLIER",
    "search": "SSE",
    "threshold": True,
    "threshold_t": 2,
    "threshold_n": 3,
    "timestamps": True,
    "sockets": True,
    "roles": {
        "client": ["submit", "view_own"],
        "server": ["verify", "search", "view_all", "tamper_test"],
        "analyst": ["aggregate", "threshold_decrypt"],
        "auditor": ["view_hashes", "audit"],
    },
    "out": "answer",
}

# Ready-made scenarios. Each one only overrides what differs from DEFAULTS.
PRESETS = {
    "evoting": {
        "_about": "end-sem sample paper: secure electronic voting system",
        "system_name": "SecureVote", "record_word": "ballot",
        "tag_word": "ConstituencyID", "value_word": "CandidateID",
        "cipher": "AES-256", "mode": "CBC", "wrap": "RSA", "hash": "sha512",
        "sign": "ELGAMAL", "he": "PAILLIER", "search": "SSE",
        "threshold": True, "timestamps": True, "sockets": True,
        "roles": {
            "voter": ["submit", "view_own"],
            "server": ["verify", "search", "view_all", "tamper_test"],
            "tally": ["aggregate", "threshold_decrypt"],
            "auditor": ["view_hashes", "audit"],
        },
    },
    "trade": {
        "_about": "financial trade reports, RSA signatures, encrypted totals",
        "system_name": "SecureTrade", "record_word": "report",
        "tag_word": "branch", "value_word": "amount",
        "cipher": "AES-256", "mode": "CBC", "wrap": "RSA", "hash": "sha256",
        "sign": "RSA", "he": "PAILLIER", "search": "SSE",
        "threshold": False, "timestamps": True, "sockets": True,
        "roles": {
            "trader": ["submit", "view_own"],
            "server": ["verify", "search", "view_all", "tamper_test"],
            "analyst": ["aggregate", "threshold_decrypt"],
            "auditor": ["view_hashes", "audit"],
        },
    },
    "medical": {
        "_about": "hospital records, ECDSA, encrypted comparison of readings",
        "system_name": "MediSecure", "record_word": "report",
        "tag_word": "ward", "value_word": "reading",
        "cipher": "AES-256", "mode": "CBC", "wrap": "RSA", "hash": "sha512",
        "sign": "ECDSA", "he": "ELGAMAL_MUL", "search": "SSE",
        "threshold": False, "timestamps": True, "sockets": True,
        "roles": {
            "patient": ["submit", "view_own"],
            "doctor": ["verify", "search", "view_all", "tamper_test"],
            "researcher": ["aggregate", "threshold_decrypt"],
            "auditor": ["view_hashes", "audit"],
        },
    },
    "banking": {
        "_about": "bank transactions, DSA signatures, multiplicative RSA",
        "system_name": "SecureBank", "record_word": "transaction",
        "tag_word": "branch", "value_word": "amount",
        "cipher": "AES-128", "mode": "CBC", "wrap": "RSA", "hash": "sha256",
        "sign": "DSA", "he": "RSA_MUL", "search": "PKSE",
        "threshold": False, "timestamps": True, "sockets": True,
        "roles": {
            "customer": ["submit", "view_own"],
            "officer": ["verify", "search", "view_all", "tamper_test"],
            "manager": ["aggregate", "threshold_decrypt"],
            "auditor": ["view_hashes", "audit"],
        },
    },
    "documents": {
        "_about": "Lab 8 shaped question: encrypted document store with search",
        "system_name": "SecureDocs", "record_word": "document",
        "tag_word": "category", "value_word": "size",
        "cipher": "AES-256", "mode": "CBC", "wrap": "RSA", "hash": "sha256",
        "sign": "RSA", "he": "NONE", "search": "SSE",
        "threshold": False, "timestamps": True, "sockets": False,
        "roles": {
            "owner": ["submit", "view_own"],
            "server": ["verify", "search", "view_all", "tamper_test"],
            "reader": ["aggregate", "threshold_decrypt"],
            "auditor": ["view_hashes", "audit"],
        },
    },
    "minimal": {
        "_about": "smallest answer that still earns ED + DSS + Hash marks",
        "system_name": "SecureStore", "record_word": "record",
        "cipher": "AES-256", "mode": "CBC", "wrap": "NONE", "hash": "sha256",
        "sign": "RSA", "he": "NONE", "search": "NONE",
        "threshold": False, "timestamps": False, "sockets": False,
        "roles": {
            "user": ["submit", "view_own"],
            "server": ["verify", "view_all", "tamper_test"],
            "auditor": ["view_hashes", "audit"],
        },
    },
}


# ---------------------------------------------------------------------------
# TEMPLATE MACHINERY
#   The answer file is assembled out of the text blocks below.
#   <<TOKEN>> markers are replaced with the values you chose.
# ---------------------------------------------------------------------------

def fill(text, cfg):
    cls, klen, bs = CIPHER_INFO[cfg["cipher"]]
    table = {
        "<<SYS>>": cfg["system_name"],
        "<<REC>>": cfg["record_word"],
        "<<RECCAP>>": cfg["record_word"][:1].upper() + cfg["record_word"][1:],
        "<<TAG>>": cfg["tag_word"],
        "<<VAL>>": cfg["value_word"],
        "<<CLS>>": cls,
        "<<CIPHER>>": cfg["cipher"],
        "<<KLEN>>": str(klen),
        "<<BS>>": str(bs),
        "<<MODE>>": cfg["mode"],
        "<<HASHFN>>": HASH_INFO[cfg["hash"]][0],
        "<<HASHNAME>>": cfg["hash"],
        "<<HALF>>": str(HASH_INFO[cfg["hash"]][1] // 2),
        "<<RSABITS>>": str(cfg["rsa_bits"]),
        "<<TT>>": str(cfg["threshold_t"]),
        "<<TN>>": str(cfg["threshold_n"]),
    }
    for key, value in table.items():
        text = text.replace(key, value)
    return text


def banner(title):
    return "\n# ---------- " + title + " ----------\n\n"


# ===========================================================================
# BLOCK: header, imports and settings
# ===========================================================================

def block_head(cfg):
    cls = CIPHER_INFO[cfg["cipher"]][0]
    lines = ["# <<SYS>> - Information Security Lab (ICT 3141)",
             "# <<CIPHER>> / <<MODE>> | <<HASHNAME>> | <<SIGNNAME>> signature"]
    extra = []
    if cfg["wrap"] != "NONE":
        extra.append(cfg["wrap"] + " key wrapping")
    if cfg["he"] != "NONE":
        extra.append(HE_LABEL[cfg["he"]])
    if cfg["search"] != "NONE":
        extra.append(cfg["search"] + " searchable index")
    if cfg["threshold"] and cfg["he"] != "NONE":
        extra.append("<<TT>>-of-<<TN>> threshold decryption")
    extra.append("role based access control")
    lines.append("# " + " | ".join(extra))
    lines.append("# generated by endsheet.py on " + datetime.now().strftime("%Y-%m-%d %H:%M"))
    lines.append("#")
    lines.append("# RUN")
    lines.append("#   python <<OUT>>.py            interactive menu  <- this is what is marked")
    lines.append("#   python <<OUT>>.py demo       full run, no typing, prints every output")
    if cfg["sockets"]:
        lines.append("#   python <<OUT>>.py netdemo    real TCP client-server submission")
        lines.append("#   python <<OUT>>.py server     listen on 127.0.0.1:9099   (terminal 1)")
        lines.append("#   python <<OUT>>.py client     submit over TCP            (terminal 2)")
    lines.append("#   python <<OUT>>.py reset      delete the stored files and start clean")
    head = "\n".join(lines) + "\n\n"

    bootstrap = []
    if native_modules_blocked():
        bootstrap = [
            "# ---------- pure-Python crypto fallback ----------",
            "# This machine blocks pycryptodome's compiled .pyd files, so the",
            "# replacements in pylib/ are loaded first. Every Crypto import",
            "# below then works unchanged.",
            "try:",
            "    import islab",
            "except ImportError:",
            "    pass                    # already loaded, or pylib is on PYTHONPATH",
            "",
            "",
        ]

    imports = ["import os", "import sys", "import json", "import hashlib"]
    if cfg["search"] == "SSE":
        imports.append("import hmac")
    if cfg["sign"] in ("ELGAMAL", "SCHNORR") or cfg["he"] in ("PAILLIER", "ELGAMAL_MUL",
                                                              "RSA_MUL") or cfg["search"] == "PKSE":
        imports.append("import random")
    if cfg["search"] == "PKSE":
        imports.append("import re")
    if cfg["sockets"]:
        imports += ["import time", "import socket", "import threading"]
    imports.append("from datetime import datetime, timedelta")
    imports.append("")

    crypto = ["from Crypto.Cipher import <<CLS>>"]
    if cfg["mode"] in ("CBC", "ECB"):
        crypto.append("from Crypto.Util.Padding import pad, unpad")
    crypto.append("from Crypto.Random import get_random_bytes")
    if cfg["wrap"] == "RSA" or cfg["sign"] == "RSA" or cfg["he"] == "RSA_MUL":
        crypto.append("from Crypto.PublicKey import RSA")
    if cfg["wrap"] == "RSA":
        crypto.append("from Crypto.Cipher import PKCS1_OAEP")
    if cfg["wrap"] == "ECC" or cfg["sign"] == "ECDSA":
        crypto.append("from Crypto.PublicKey import ECC")
    if cfg["wrap"] == "ECC":
        crypto.append("from Crypto.Protocol.KDF import HKDF")
        if cls != "AES":
            crypto.append("from Crypto.Cipher import AES")
    if cfg["sign"] == "RSA":
        crypto.append("from Crypto.Signature import pkcs1_15")
    if cfg["sign"] == "DSA":
        crypto.append("from Crypto.PublicKey import DSA")
    if cfg["sign"] in ("DSA", "ECDSA"):
        crypto.append("from Crypto.Signature import DSS")
    if cfg["sign"] in ("RSA", "DSA", "ECDSA") or cfg["wrap"] == "ECC":
        crypto.append("from Crypto.Hash import SHA256")
    if cfg["sign"] in ("ELGAMAL", "SCHNORR") or cfg["he"] in ("PAILLIER", "ELGAMAL_MUL") \
            or cfg["search"] == "PKSE":
        crypto.append("from Crypto.Util.number import getPrime, GCD"
                      + (", isPrime" if cfg["sign"] == "SCHNORR" else ""))
    crypto.append("")

    guard = ("try:\n"
             "    sys.stdout.reconfigure(errors=\"replace\")\n"
             "except Exception:\n"
             "    pass            # old Python, or a console that cannot do UTF-8\n\n")

    settings = ["# ===== SETTINGS - change these to match the question =====",
                "system_name = \"<<SYS>>\"",
                "record_word = \"<<REC>>\""]
    roles_text = ["roles = {"]
    items = list(cfg["roles"].items())
    for i, (role, actions) in enumerate(items):
        comma = "," if i < len(items) - 1 else ""
        roles_text.append("    \"%s\": %s%s" % (role, json.dumps(actions).replace('"', '"'), comma))
    roles_text.append("}")
    settings += roles_text
    settings.append("key_bytes = <<KLEN>>                   # <<CIPHER>> key length")
    if cfg["wrap"] == "RSA":
        settings.append("rsa_bits = <<RSABITS>>                 # 4096 also works, keygen is slower")
    if cfg["sign"] in ("ELGAMAL", "SCHNORR"):
        settings.append("sign_bits = 256                # size of the signature prime p")
    if cfg["he"] == "PAILLIER":
        settings.append("paillier_bits = 512            # size of the Paillier modulus n")
    if cfg["he"] in ("RSA_MUL", "ELGAMAL_MUL"):
        settings.append("he_bits = 512                  # size of the homomorphic modulus")
    if cfg["search"] == "PKSE":
        settings.append("pkse_bits = 512                # Paillier modulus used by the index")
    if cfg["threshold"] and cfg["he"] != "NONE":
        settings.append("threshold_t = <<TT>>                  # shares needed to decrypt the total")
        settings.append("threshold_n = <<TN>>                  # shares handed out")
    if cfg["timestamps"]:
        settings.append("window_opens = \"2000-01-01 00:00:00\"   # earliest accepted timestamp")
        settings.append("window_closes = \"2099-12-31 23:59:59\"  # deadline")
    if cfg["he"] == "PAILLIER":
        settings.append("categories = {1: \"option one\", 2: \"option two\", 3: \"option three\"}")
    if cfg["sockets"]:
        settings.append("host, port = \"127.0.0.1\", 9099")
    settings.append("# ===== END SETTINGS =====\n")

    state = ["records = {}                    # <<REC>> id -> stored envelope"]
    if cfg["search"] != "NONE":
        state.append("search_index = {}               # search token -> encrypted <<REC>> ids")
    if cfg["search"] == "PKSE":
        state.append("id_of_number = {}               # Paillier plaintext -> <<REC>> id")
    state.append("signer_keys = {}                # user name -> signing key material")
    state.append("record_file = \"records.json\"")
    state.append("key_file = \"keys.json\"")
    state.append("log_file = \"audit.log\"")
    if cfg["he"] == "PAILLIER":
        state.append("MAX_ITEMS = 10 ** 6             # base used to pack the per-category counters")
    state.append("")

    return (head + "\n".join(bootstrap) + "\n".join(imports) + "\n"
            + "\n".join(crypto) + "\n" + guard
            + "\n".join(settings) + "\n" + "\n".join(state) + "\n")


HE_LABEL = {
    "PAILLIER": "Paillier additive homomorphic aggregation",
    "RSA_MUL": "RSA multiplicative homomorphic aggregation",
    "ELGAMAL_MUL": "ElGamal multiplicative homomorphic aggregation",
    "NONE": "",
}

SIGN_LABEL = {"ELGAMAL": "ElGamal", "RSA": "RSA", "DSA": "DSA",
              "ECDSA": "ECDSA", "SCHNORR": "Schnorr"}


# ===========================================================================
# BLOCK: small helpers
# ===========================================================================

BLOCK_HELPERS = '''
def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def short(value, n=44):
    text = str(value)
    return text if len(text) <= n else text[:n] + "..."


def hexs(value):
    # one place that turns anything into the hexadecimal the question asks for
    if isinstance(value, bytes):
        return value.hex().upper()
    if isinstance(value, int):
        return hex(value)
    return str(value)
'''


# ===========================================================================
# BLOCK: symmetric encryption and decryption  (the ED mark)
# ===========================================================================

NEW_KEY_PLAIN = '''
def new_key():
    # a fresh <<CIPHER>> session key for every <<REC>>
    return get_random_bytes(key_bytes)
'''

NEW_KEY_DES3 = '''
def new_key():
    # 3DES refuses a key whose three parts are not all different,
    # so keep drawing until pycryptodome accepts it
    while True:
        candidate = get_random_bytes(24)
        try:
            DES3.new(candidate, DES3.MODE_ECB)
            return candidate
        except ValueError:
            continue
'''

ED_BODIES = {
    "CBC": ('''
def encrypt_data(key, data):
    # <<CIPHER>> in CBC mode: fresh random IV every time, PKCS#7 padding
    iv = get_random_bytes(<<BS>>)
    cipher = <<CLS>>.new(key, <<CLS>>.MODE_CBC, iv)
    return iv, cipher.encrypt(pad(data.encode(), <<BS>>))


def decrypt_data(key, iv, ciphertext):
    cipher = <<CLS>>.new(key, <<CLS>>.MODE_CBC, iv)
    # errors="replace" so a tampered block prints instead of crashing the run
    return unpad(cipher.decrypt(ciphertext), <<BS>>).decode(errors="replace")
'''),
    "ECB": ('''
def encrypt_data(key, data):
    # ECB has no IV at all - identical blocks give identical ciphertext,
    # which is exactly why nobody should use it for real data
    cipher = <<CLS>>.new(key, <<CLS>>.MODE_ECB)
    return b"", cipher.encrypt(pad(data.encode(), <<BS>>))


def decrypt_data(key, iv, ciphertext):
    cipher = <<CLS>>.new(key, <<CLS>>.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), <<BS>>).decode(errors="replace")
'''),
    "CFB": ('''
def encrypt_data(key, data):
    # CFB turns the block cipher into a stream cipher: no padding needed
    iv = get_random_bytes(<<BS>>)
    cipher = <<CLS>>.new(key, <<CLS>>.MODE_CFB, iv)
    return iv, cipher.encrypt(data.encode())


def decrypt_data(key, iv, ciphertext):
    cipher = <<CLS>>.new(key, <<CLS>>.MODE_CFB, iv)
    return cipher.decrypt(ciphertext).decode(errors="replace")
'''),
    "OFB": ('''
def encrypt_data(key, data):
    # OFB is also a stream mode: keystream only, no padding
    iv = get_random_bytes(<<BS>>)
    cipher = <<CLS>>.new(key, <<CLS>>.MODE_OFB, iv)
    return iv, cipher.encrypt(data.encode())


def decrypt_data(key, iv, ciphertext):
    cipher = <<CLS>>.new(key, <<CLS>>.MODE_OFB, iv)
    return cipher.decrypt(ciphertext).decode(errors="replace")
'''),
    "CTR": ('''
def encrypt_data(key, data):
    # CTR mode: the random value is a nonce, not an IV, and it is never reused
    nonce = get_random_bytes(<<BS>> // 2)
    cipher = <<CLS>>.new(key, <<CLS>>.MODE_CTR, nonce=nonce)
    return nonce, cipher.encrypt(data.encode())


def decrypt_data(key, iv, ciphertext):
    cipher = <<CLS>>.new(key, <<CLS>>.MODE_CTR, nonce=iv)
    return cipher.decrypt(ciphertext).decode(errors="replace")
'''),
}


# ===========================================================================
# BLOCK: wrapping the session key with a public key  (second half of ED)
# ===========================================================================

WRAP_RSA = '''
def server_keys():
    # the receiving party's RSA key pair, cached so a rerun is instant
    if os.path.exists("server_private.pem"):
        key = RSA.import_key(open("server_private.pem", "rb").read())
    else:
        key = RSA.generate(rsa_bits)
        open("server_private.pem", "wb").write(key.export_key())
        open("server_public.pem", "wb").write(key.publickey().export_key())
    return key, key.publickey()


def wrap_key(session_key, public_key):
    # the session key travels encrypted under the public key (RSA-OAEP)
    return PKCS1_OAEP.new(public_key).encrypt(session_key)


def unwrap_key(blob, private_key):
    return PKCS1_OAEP.new(private_key).decrypt(blob)
'''

WRAP_ECC = '''
def server_keys():
    # the receiving party's ECC key pair on the NIST P-256 curve
    if os.path.exists("server_private.pem"):
        key = ECC.import_key(open("server_private.pem").read())
    else:
        key = ECC.generate(curve="P-256")
        open("server_private.pem", "w").write(key.export_key(format="PEM"))
        open("server_public.pem", "w").write(key.public_key().export_key(format="PEM"))
    return key, key.public_key()


def ecdh_shared(private_key, public_key):
    # ECDH: multiply the other side's point by your own scalar
    point = public_key.pointQ * private_key.d
    raw = point.x.to_bytes(point.size_in_bytes(), "big")
    return HKDF(raw, 32, b"", SHA256)


def wrap_key(session_key, public_key):
    # ECIES: ephemeral ECDH to a one-time AES key, then AES-GCM the session key
    ephemeral = ECC.generate(curve="P-256")
    kek = ecdh_shared(ephemeral, public_key)
    cipher = AES.new(kek, AES.MODE_GCM)
    body, tag = cipher.encrypt_and_digest(session_key)
    eph = ephemeral.public_key().export_key(format="DER")
    return len(eph).to_bytes(2, "big") + eph + cipher.nonce + tag + body


def unwrap_key(blob, private_key):
    size = int.from_bytes(blob[:2], "big")
    eph = ECC.import_key(blob[2:2 + size])
    rest = blob[2 + size:]
    kek = ecdh_shared(private_key, eph)
    cipher = AES.new(kek, AES.MODE_GCM, nonce=rest[:16])
    return cipher.decrypt_and_verify(rest[32:], rest[16:32])
'''

WRAP_NONE = '''
def server_keys():
    # no public-key wrapping in this question: both sides already share the key
    fixed = hashlib.sha256(system_name.encode()).digest()[:key_bytes]
    return fixed, fixed


def wrap_key(session_key, public_key):
    # nothing to wrap - the session key is the pre-shared key
    return session_key


def unwrap_key(blob, private_key):
    return blob
'''


# ===========================================================================
# BLOCK: hashing  (the Hash mark)
# ===========================================================================

BLOCK_HASH = '''
def hash_data(data):
    # <<HASHNAME>> digest of the <<REC>>, printed and stored as hexadecimal
    if isinstance(data, str):
        data = data.encode()
    return <<HASHFN>>(data).hexdigest()


def hash_matches(data, stored_hex):
    # recomputing and comparing is what "integrity verification" means
    return hash_data(data) == stored_hex
'''


# ===========================================================================
# BLOCK: digital signature  (the DSS mark)
#   Every variant provides the same four functions, so the rest of the
#   program never changes when you swap the scheme.
# ===========================================================================

SIGN_BLOCKS = {
"ELGAMAL": '''
def make_signing_key():
    # ElGamal: p prime, g generator, x private, y = g^x mod p
    p = getPrime(sign_bits)
    g = 2
    x = random.randrange(2, p - 2)
    return {"p": p, "g": g, "y": pow(g, x, p), "x": x}


def sign_hash(digest_hex, key):
    # s = (H - x*r) * k^-1 mod (p-1),  r = g^k mod p
    p, g, x = key["p"], key["g"], key["x"]
    h = int(digest_hex, 16) % (p - 1)
    while True:
        k = random.randrange(2, p - 2)
        if GCD(k, p - 1) == 1:
            break                      # k must be invertible mod p-1
    r = pow(g, k, p)
    s = ((h - x * r) * pow(k, -1, p - 1)) % (p - 1)
    return [r, s]


def verify_hash(digest_hex, signature, key):
    # valid when g^H == y^r * r^s  (mod p)
    p, g, y = key["p"], key["g"], key["y"]
    r, s = int(signature[0]), int(signature[1])
    if not 0 < r < p:
        return False
    h = int(digest_hex, 16) % (p - 1)
    return pow(g, h, p) == (pow(y, r, p) * pow(r, s, p)) % p


def sig_text(signature):
    return "(r, s) = (%s, %s)" % (short(signature[0], 30), short(signature[1], 30))
''',
"SCHNORR": '''
def make_signing_key():
    # Schnorr needs q | p-1 : pick q, then search for a prime p = k*q + 1
    q = getPrime(160)
    while True:
        k = random.randrange(1 << (sign_bits - 161), 1 << (sign_bits - 160))
        p = k * q + 1
        if isPrime(p):
            break
    h = 2
    g = pow(h, (p - 1) // q, p)
    while g == 1:
        h += 1
        g = pow(h, (p - 1) // q, p)
    x = random.randrange(1, q)
    return {"p": p, "q": q, "g": g, "y": pow(g, x, p), "x": x}


def sign_hash(digest_hex, key):
    # r = g^k mod p ; e = H(r || m) mod q ; s = (k + x*e) mod q
    p, q, g, x = key["p"], key["q"], key["g"], key["x"]
    k = random.randrange(1, q)
    r = pow(g, k, p)
    e = int(hashlib.sha256((str(r) + digest_hex).encode()).hexdigest(), 16) % q
    s = (k + x * e) % q
    return [e, s]


def verify_hash(digest_hex, signature, key):
    # rebuild r from s and e, then check the hash again
    p, q, g, y = key["p"], key["q"], key["g"], key["y"]
    e, s = int(signature[0]), int(signature[1])
    r = (pow(g, s, p) * pow(y, -e, p)) % p
    check = int(hashlib.sha256((str(r) + digest_hex).encode()).hexdigest(), 16) % q
    return check == e


def sig_text(signature):
    return "(e, s) = (%s, %s)" % (short(signature[0], 30), short(signature[1], 30))
''',
"RSA": '''
def make_signing_key():
    # one RSA key pair per signer, stored as PEM text so it survives in JSON
    key = RSA.generate(2048)
    return {"private": key.export_key().decode(),
            "public": key.publickey().export_key().decode()}


def sign_hash(digest_hex, key):
    # sign the digest string: s = H(digest)^d mod n, with PKCS#1 v1.5 padding
    private = RSA.import_key(key["private"])
    h = SHA256.new(digest_hex.encode())
    return pkcs1_15.new(private).sign(h).hex()


def verify_hash(digest_hex, signature, key):
    public = RSA.import_key(key["public"])
    h = SHA256.new(digest_hex.encode())
    try:
        pkcs1_15.new(public).verify(h, bytes.fromhex(signature))
        return True
    except (ValueError, TypeError):
        return False                   # verify RAISES, so turn it into a bool


def sig_text(signature):
    return "sig(hex) = " + short(signature.upper(), 48)
''',
"DSA": '''
def make_signing_key():
    key = DSA.generate(2048)
    return {"private": key.export_key().decode(),
            "public": key.publickey().export_key().decode()}


def sign_hash(digest_hex, key):
    private = DSA.import_key(key["private"])
    h = SHA256.new(digest_hex.encode())
    return DSS.new(private, "fips-186-3").sign(h).hex()


def verify_hash(digest_hex, signature, key):
    public = DSA.import_key(key["public"])
    h = SHA256.new(digest_hex.encode())
    try:
        DSS.new(public, "fips-186-3").verify(h, bytes.fromhex(signature))
        return True
    except (ValueError, TypeError):
        return False


def sig_text(signature):
    return "sig(hex) = " + short(signature.upper(), 48)
''',
"ECDSA": '''
def make_signing_key():
    # ECDSA on P-256: same security as RSA-3072 with a far smaller key
    key = ECC.generate(curve="P-256")
    return {"private": key.export_key(format="PEM"),
            "public": key.public_key().export_key(format="PEM")}


def sign_hash(digest_hex, key):
    private = ECC.import_key(key["private"])
    h = SHA256.new(digest_hex.encode())
    return DSS.new(private, "fips-186-3").sign(h).hex()


def verify_hash(digest_hex, signature, key):
    public = ECC.import_key(key["public"])
    h = SHA256.new(digest_hex.encode())
    try:
        DSS.new(public, "fips-186-3").verify(h, bytes.fromhex(signature))
        return True
    except (ValueError, TypeError):
        return False


def sig_text(signature):
    return "sig(hex) = " + short(signature.upper(), 48)
''',
}


# ===========================================================================
# BLOCK: partial homomorphic encryption  (Lab 7)
#   Each variant provides he_keygen / he_encrypt / he_combine / he_decrypt
#   and says what "combine" means for that scheme.
# ===========================================================================

HE_BLOCKS = {
"PAILLIER": '''
def he_keygen():
    # cached in a file so <<REC>>s stored in an earlier run can still be totalled
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
    # c = (1 + m*n) * r^n  mod n^2      (g = n+1 makes the first part cheap)
    n, nn = pub["n"], pub["nn"]
    r = random.randrange(1, n)
    while GCD(r, n) != 1:
        r = random.randrange(1, n)
    return ((1 + m * n) * pow(r, n, nn)) % nn


def he_combine(c1, c2, pub):
    # MULTIPLYING Paillier ciphertexts ADDS the plaintexts - the whole point
    return (c1 * c2) % pub["nn"]


def he_decrypt(c, pub, secret):
    n, nn = pub["n"], pub["nn"]
    u = (pow(c, secret, nn) - 1) // n
    return (u * pow(secret, -1, n)) % n


HE_OPERATION = "addition"
''',
"RSA_MUL": '''
def he_keygen():
    # textbook RSA, no padding, so that the multiplicative property survives
    if os.path.exists("he_key.json"):
        return {k: int(v) for k, v in json.load(open("he_key.json")).items()}
    p = getPrime(he_bits // 2)
    q = getPrime(he_bits // 2)
    while p == q:
        q = getPrime(he_bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    while GCD(e, phi) != 1:
        e += 2
    key = {"n": n, "e": e, "secret": pow(e, -1, phi)}
    json.dump({k: str(v) for k, v in key.items()}, open("he_key.json", "w"))
    return key


def he_encrypt(m, pub):
    # c = m^e mod n
    return pow(m, pub["e"], pub["n"])


def he_combine(c1, c2, pub):
    # (m1^e)(m2^e) = (m1*m2)^e  ->  multiplying ciphertexts MULTIPLIES plaintexts
    return (c1 * c2) % pub["n"]


def he_decrypt(c, pub, secret):
    return pow(c, secret, pub["n"])


HE_OPERATION = "multiplication"
''',
"ELGAMAL_MUL": '''
def he_keygen():
    # ElGamal is multiplicatively homomorphic: (a1*a2, b1*b2) decrypts to m1*m2
    if os.path.exists("he_key.json"):
        return {k: int(v) for k, v in json.load(open("he_key.json")).items()}
    p = getPrime(he_bits)
    g = 2
    x = random.randrange(2, p - 2)
    key = {"p": p, "g": g, "y": pow(g, x, p), "secret": x}
    json.dump({k: str(v) for k, v in key.items()}, open("he_key.json", "w"))
    return key


def he_encrypt(m, pub):
    p, g, y = pub["p"], pub["g"], pub["y"]
    r = random.randrange(2, p - 2)
    return [pow(g, r, p), (m * pow(y, r, p)) % p]


def he_combine(c1, c2, pub):
    p = pub["p"]
    return [(int(c1[0]) * int(c2[0])) % p, (int(c1[1]) * int(c2[1])) % p]


def he_decrypt(c, pub, secret):
    p = pub["p"]
    a, b = int(c[0]), int(c[1])
    return (b * pow(a, -secret, p)) % p


HE_OPERATION = "multiplication"
''',
}


# ===========================================================================
# BLOCK: threshold decryption - Shamir t-of-n over the private exponent
# ===========================================================================

BLOCK_THRESHOLD = '''
def shamir_split(secret, t, n, prime):
    # a random polynomial whose constant term is the secret
    coeffs = [secret] + [random.randrange(1, prime) for _ in range(t - 1)]
    shares = []
    for i in range(1, n + 1):
        y = sum(c * pow(i, j, prime) for j, c in enumerate(coeffs)) % prime
        shares.append([i, y])
    return shares


def shamir_combine(shares, prime):
    # Lagrange interpolation back to the constant term
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
    # the field has to be larger than the secret we are splitting
    return getPrime(he_secret.bit_length() + 16)


def one_share_alone():
    prime = share_prime()
    shares = shamir_split(he_secret, threshold_t, threshold_n, prime)
    guess = shamir_combine(shares[:1], prime)
    print("one authority alone reconstructs :", short(guess, 30))
    print("the real private exponent is     :", short(he_secret, 30))
    print("-> a single authority learns nothing, which is what threshold means")
'''


# ===========================================================================
# BLOCK: searchable encryption  (the Search mark)
# ===========================================================================

SEARCH_SSE = '''
def search_token(label):
    # HMAC under the index key: the server can MATCH tokens but cannot READ labels
    return hmac.new(index_key, label.lower().encode(), hashlib.sha256).hexdigest()


def index_add(label, record_id):
    # the posting list holds encrypted <<REC>> ids, never plain ones
    iv, ct = encrypt_data(index_key, record_id)
    search_index.setdefault(search_token(label), []).append([iv.hex(), ct.hex()])


def index_lookup(label):
    hits = []
    for iv_hex, ct_hex in search_index.get(search_token(label), []):
        hits.append(decrypt_data(index_key, bytes.fromhex(iv_hex), bytes.fromhex(ct_hex)))
    return sorted(set(hits))
'''

SEARCH_PKSE = '''
def pkse_keygen():
    # a Paillier key pair that belongs to the index, kept in its own file
    if os.path.exists("pkse_key.json"):
        return {k: int(v) for k, v in json.load(open("pkse_key.json")).items()}
    p = getPrime(pkse_bits // 2)
    q = getPrime(pkse_bits // 2)
    while p == q:
        q = getPrime(pkse_bits // 2)
    n = p * q
    key = {"n": n, "nn": n * n, "secret": (p - 1) * (q - 1)}
    json.dump({k: str(v) for k, v in key.items()}, open("pkse_key.json", "w"))
    return key


def pkse_encrypt(m):
    n, nn = pkse_key["n"], pkse_key["nn"]
    r = random.randrange(1, n)
    while GCD(r, n) != 1:
        r = random.randrange(1, n)
    return ((1 + m * n) * pow(r, n, nn)) % nn


def pkse_decrypt(c):
    n, nn, secret = pkse_key["n"], pkse_key["nn"], pkse_key["secret"]
    u = (pow(c, secret, nn) - 1) // n
    return (u * pow(secret, -1, n)) % n


def search_token(label):
    # a deterministic hash is used as the index key so lookups can match;
    # only the <<REC>> ids are public-key encrypted
    return hashlib.sha256(label.lower().encode()).hexdigest()


def index_add(label, record_id):
    number = int(re.sub(r"\\D", "", record_id) or len(id_of_number) + 1)
    id_of_number[str(number)] = record_id
    search_index.setdefault(search_token(label), []).append(str(pkse_encrypt(number)))


def index_lookup(label):
    hits = []
    for blob in search_index.get(search_token(label), []):
        number = pkse_decrypt(int(blob))
        hits.append(id_of_number.get(str(number), "doc" + str(number)))
    return sorted(set(hits))
'''

SEARCH_COMMON = '''
def minute_bucket(stamp):
    return "time:" + stamp[:16]


def search_by_tag(value):
    return index_lookup("<<TAG>>:" + str(value))


def search_by_time_range(start, end):
    # a range query is just every one-minute bucket between the two ends
    t0 = datetime.strptime(start, "%Y-%m-%d %H:%M")
    t1 = datetime.strptime(end, "%Y-%m-%d %H:%M")
    found = []
    while t0 <= t1:
        found += index_lookup(minute_bucket(t0.strftime("%Y-%m-%d %H:%M")))
        t0 += timedelta(minutes=1)
    return sorted(set(found))
'''


# ===========================================================================
# BLOCK: storage, audit log and access control
# ===========================================================================

BLOCK_STORE = '''
def save_all():
    json.dump(records, open(record_file, "w"), indent=2)
    json.dump(signer_keys, open(key_file, "w"), indent=2)
<<SAVE_EXTRA>>

def load_all():
    global records, signer_keys<<LOAD_GLOBALS>>
    if os.path.exists(record_file):
        records = json.load(open(record_file))
    if os.path.exists(key_file):
        signer_keys = json.load(open(key_file))
<<LOAD_EXTRA>>

def get_signing_key(user):
    if user not in signer_keys:
        signer_keys[user] = make_signing_key()
        log_action(user, "<<SIGNNAME>> key pair generated")
    return signer_keys[user]
'''

BLOCK_AUDIT = '''
def log_action(who, what):
    # an append-only trail: who did what, and when
    open(log_file, "a").write("%s | %s | %s\\n" % (timestamp(), who, what))


def show_log():
    if not os.path.exists(log_file):
        print("audit log is empty")
        return
    for line in open(log_file):
        print(line.rstrip())
'''

BLOCK_RBAC = '''
def check_permission(role, action):
    # role based access control: one table, checked before every operation
    if action not in roles.get(role, []):
        print("ACCESS DENIED:", role, "cannot", action)
        log_action(role, "DENIED " + action)
        return False
    return True
'''


# ===========================================================================
# BLOCK: the client side - build and submit one <<REC>>
# ===========================================================================

def block_client(cfg):
    L = ['def submit_record(user, record_id, value, tag, when=None):',
         '    if not check_permission(client_role, "submit"):',
         '        return None',
         '',
         '    # 1 the <<REC>> itself, exactly the fields the question lists',
         '    body = "<<VAL>>=%s;<<TAG>>=%s" % (value, tag)',
         '    print("<<RECCAP>> UTF-8:", body)',
         '',
         '    # 2 <<HASHNAME>> for integrity',
         '    digest = hash_data(body)']
    if HASH_INFO[cfg["hash"]][1] > 64:
        pad = " " * (len("Output (hex):") + len(cfg["hash"]) - 1)
        L += ['    print("Output <<HASHNAME>>(hex):", digest[:<<HALF>>])',
              '    print("' + pad + '", digest[<<HALF>>:])']
    else:
        L += ['    print("Output <<HASHNAME>>(hex):", digest)']
    L += ['',
          '    # 3 <<CIPHER>> in <<MODE>> mode for confidentiality',
          '    session_key = new_key()',
          '    iv, ciphertext = encrypt_data(session_key, body)']
    if cfg["mode"] != "ECB":
        L += ['    print("Output %s(hex):" % ("nonce" if "<<MODE>>" == "CTR" else "IV"), hexs(iv))']
    L += ['    print("Output <<CIPHER>>-<<MODE>> CT(hex):", hexs(ciphertext))']
    if cfg["wrap"] != "NONE":
        L += ['',
              '    # 4 the session key is wrapped with the receiver public key',
              '    wrapped = wrap_key(session_key, server_public)',
              '    print("Output session key wrapped with <<WRAPNAME>>: [%d bytes] %s"',
              '          % (len(wrapped), short(hexs(wrapped), 32)))']
    else:
        L += ['', '    wrapped = wrap_key(session_key, server_public)   # pre-shared, nothing to wrap']
    L += ['',
          '    # 5 <<SIGNNAME>> signature over the digest: authenticity + non-repudiation',
          '    signing_key = get_signing_key(user)',
          '    signature = sign_hash(digest, signing_key)',
          '    print("Output <<SIGNNAME>> signature:", sig_text(signature))']
    if cfg["he"] != "NONE":
        L += ['',
              '    # 6 the numeric <<VAL>> is encrypted homomorphically, so the',
              '    #   server can total it later without ever decrypting one <<REC>>',
              '    value_ct = he_encrypt(int(value), he_pub)']
        if cfg["he"] == "PAILLIER":
            L += ['    packed_ct = he_encrypt(MAX_ITEMS ** int(value), he_pub)']
        L += ['    print("Output homomorphic <<VAL>> CT(hex):", short(hexs(value_ct), 26))']
    if cfg["timestamps"]:
        L += ['',
              '    # 7 trusted timestamp, checked against the deadline on the server',
              '    stamp = when or timestamp()',
              '    print("Timestamp:", stamp)']
    else:
        L += ['', '    stamp = when or timestamp()']
    L += ['',
          '    records[record_id] = {',
          '        "user": user,',
          '        "tag": str(tag),',
          '        "iv": iv.hex(),',
          '        "ciphertext": ciphertext.hex(),',
          '        "wrapped_key": wrapped.hex(),',
          '        "hash": digest,',
          '        "signature": signature,']
    if cfg["he"] != "NONE":
        L += ['        "value_ct": str(value_ct),']
        if cfg["he"] == "PAILLIER":
            L += ['        "packed_ct": str(packed_ct),']
        elif cfg["he"] == "ELGAMAL_MUL":
            L[-1] = '        "value_ct": [str(value_ct[0]), str(value_ct[1])],'
    L += ['        "timestamp": stamp,',
          '        "status": "submitted"',
          '    }']
    if cfg["search"] != "NONE":
        L += ['    index_add("<<TAG>>:" + str(tag), record_id)        # searchable metadata',
              '    index_add(minute_bucket(stamp), record_id)']
    L += ['    save_all()',
          '    log_action(user, "submit " + record_id)',
          '    print("Output:", record_id, "submitted'
          + ('; searchable metadata indexed")' if cfg["search"] != "NONE" else '")'),
          '    return record_id',
          '']
    return "\n".join(L) + "\n"


# ===========================================================================
# BLOCK: the server side - verify one <<REC>>
# ===========================================================================

def block_server(cfg):
    L = []
    if cfg["timestamps"]:
        L += ['def within_window(stamp):',
              '    # votes / reports after the deadline are rejected',
              '    return window_opens <= stamp <= window_closes',
              '',
              '']
    L += ['def verify_record(record_id):',
          '    if not check_permission(server_role, "verify"):',
          '        return False',
          '    if record_id not in records:',
          '        print("no such <<REC>>:", record_id)',
          '        return False',
          '',
          '    row = records[record_id]',
          '',
          '    # 1 unwrap the session key with the private key',
          '    session_key = unwrap_key(bytes.fromhex(row["wrapped_key"]), server_private)']
    if cfg["wrap"] != "NONE":
        L += ['    print("Output: private-key unwrap successful")']
    L += ['',
          '    # 2 decrypt the <<REC>>',
          '    try:',
          '        body = decrypt_data(session_key, bytes.fromhex(row["iv"]),',
          '                            bytes.fromhex(row["ciphertext"]))',
          '    except ValueError:',
          '        body = ""                       # padding destroyed -> definitely tampered',
          '    print("Decrypted <<REC>>:", body or "<unreadable, padding broken>")',
          '',
          '    # 3 verify the signature with the submitter public key',
          '    sig_ok = verify_hash(row["hash"], row["signature"], signer_keys[row["user"]])',
          '    print("Output: <<SIGNNAME>> signature", "valid" if sig_ok else "INVALID")',
          '',
          '    # 4 recompute the hash and compare',
          '    hash_ok = hash_matches(body, row["hash"])',
          '    print("Output: recomputed <<HASHNAME>>",',
          '          "matches stored hash" if hash_ok else "DOES NOT MATCH")']
    if cfg["timestamps"]:
        L += ['',
              '    # 5 check the timestamp against the allowed window',
              '    time_ok = within_window(row["timestamp"])',
              '    print("Output: timestamp",',
              '          "within the valid period" if time_ok else "OUTSIDE the valid period")']
    else:
        L += ['    time_ok = True']
    L += ['',
          '    accepted = sig_ok and hash_ok and time_ok',
          '    row["status"] = "accepted" if accepted else "rejected"',
          '    save_all()',
          '    log_action(server_role, "verify %s -> %s" % (record_id, row["status"]))',
          '    print("Output:", record_id, row["status"]'
          + (' + "; encrypted <<VAL>> left untouched")' if cfg["he"] != "NONE" else ')'),
          '    return accepted',
          '',
          '',
          'def tamper_record(record_id):',
          '    # flip one byte of the stored ciphertext to prove the hash check works',
          '    if not check_permission(server_role, "tamper_test"):',
          '        return',
          '    row = records[record_id]',
          '    raw = bytearray(bytes.fromhex(row["ciphertext"]))',
          '    raw[0] ^= 0x01                      # first block: padding survives',
          '    row["ciphertext"] = bytes(raw).hex()',
          '    save_all()',
          '    print("tampered with the stored ciphertext of", record_id, "- now re-verify it")',
          '    log_action(server_role, "tamper test on " + record_id)',
          '']
    return "\n".join(L) + "\n"


# ===========================================================================
# BLOCK: encrypted aggregation and threshold reveal
# ===========================================================================

def block_agg(cfg):
    if cfg["he"] == "NONE":
        return ""
    L = ['def aggregate(ids=None):',
         '    if not check_permission(analyst_role, "aggregate"):',
         '        return None',
         '    ids = ids or [k for k, v in records.items() if v["status"] == "accepted"]',
         '    if not ids:',
         '        print("nothing accepted yet - verify the <<REC>>s first")',
         '        return None',
         '']
    if cfg["he"] == "PAILLIER":
        L += ['    total = he_encrypt(0, he_pub)            # encrypted zero to start from',
              '    packed = he_encrypt(0, he_pub)',
              '    for rid in ids:',
              '        total = he_combine(total, int(records[rid]["value_ct"]), he_pub)',
              '        packed = he_combine(packed, int(records[rid]["packed_ct"]), he_pub)']
    elif cfg["he"] == "RSA_MUL":
        L += ['    total = he_encrypt(1, he_pub)            # encrypted one to start from',
              '    for rid in ids:',
              '        total = he_combine(total, int(records[rid]["value_ct"]), he_pub)',
              '    packed = None']
    else:
        L += ['    total = he_encrypt(1, he_pub)            # encrypted one to start from',
              '    for rid in ids:',
              '        total = he_combine(total, records[rid]["value_ct"], he_pub)',
              '    packed = None']
    L += ['',
          '    print("Combined", len(ids), "encrypted <<VAL>>s:", ", ".join(ids))',
          '    print("Output: homomorphic", HE_OPERATION, "on ciphertexts =",',
          '          short(hexs(total if not isinstance(total, list) else total[1]), 26))',
          '    print("Output: no single <<REC>> was decrypted to get this")',
          '    return total, packed',
          '',
          '']
    if cfg["threshold"]:
        L += ['def reveal(combined):',
              '    if not check_permission(analyst_role, "threshold_decrypt"):',
              '        return None',
              '    total, packed = combined',
              '',
              '    # the private exponent is never held by one party: it is split',
              '    prime = share_prime()',
              '    shares = shamir_split(he_secret, threshold_t, threshold_n, prime)',
              '    print("Threshold scheme: <<TT>>-of-<<TN>> Shamir shares of the private exponent")',
              '    presented = shares[:threshold_t]',
              '    print("Threshold authorization: %d shares presented -> sufficient"',
              '          % len(presented))',
              '    secret = shamir_combine(presented, prime)',
              '    if secret != he_secret:',
              '        print("share reconstruction FAILED")',
              '        return None',
              '']
    else:
        L += ['def reveal(combined):',
              '    if not check_permission(analyst_role, "threshold_decrypt"):',
              '        return None',
              '    total, packed = combined',
              '    secret = he_secret',
              '']
    L += ['    answer = he_decrypt(total, he_pub, secret)',
          '    print("Output: decrypted", HE_OPERATION, "of all <<VAL>>s =", answer)']
    if cfg["he"] == "PAILLIER":
        L += ['    counts = he_decrypt(packed, he_pub, secret)',
              '    print("Output: per-category counts (individual <<REC>>s never decrypted)")',
              '    for cid, name in sorted(categories.items()):',
              '        print("   %-3d %-14s count = %d"',
              '              % (cid, name, (counts // (MAX_ITEMS ** cid)) % MAX_ITEMS))']
    L += ['    log_action(analyst_role, "aggregate revealed")',
          '    return answer',
          '']
    return "\n".join(L) + "\n"


# ===========================================================================
# BLOCK: views
# ===========================================================================

BLOCK_VIEWS = '''
def view_own(user):
    if not check_permission(client_role, "view_own"):
        return
    for rid, row in records.items():
        if row["user"] == user:
            print(rid, "|", row["tag"], "|", row["timestamp"], "|", row["status"])


def view_all():
    if not check_permission(server_role, "view_all"):
        return
    print("%-10s %-10s %-8s %-20s %s" % ("ID", "USER", "<<TAG>>"[:8].upper(),
                                         "TIMESTAMP", "STATUS"))
    for rid, row in records.items():
        print("%-10s %-10s %-8s %-20s %s" % (rid, row["user"], row["tag"],
                                             row["timestamp"], row["status"]))


def show_hashes():
    # the auditor sees integrity data only, never the plaintext
    if not check_permission(auditor_role, "view_hashes"):
        return
    for rid, row in records.items():
        print(rid, ":", row["hash"][:32] + "...", "|", sig_text(row["signature"]))
'''


# ===========================================================================
# BLOCK: client-server over TCP  (the Client-Server mark)
# ===========================================================================

def block_net(cfg):
    if not cfg["sockets"]:
        return ""
    L = ['def send_frame(sock, obj):',
         '    # 4-byte big-endian length, then the JSON payload',
         '    data = json.dumps(obj).encode()',
         '    sock.sendall(len(data).to_bytes(4, "big") + data)',
         '',
         '',
         'def recv_exact(sock, count):',
         '    buf = b""',
         '    while len(buf) < count:',
         '        chunk = sock.recv(count - len(buf))',
         '        if not chunk:',
         '            raise ConnectionError("connection closed")',
         '        buf += chunk',
         '    return buf',
         '',
         '',
         'def recv_frame(sock):',
         '    size = int.from_bytes(recv_exact(sock, 4), "big")',
         '    return json.loads(recv_exact(sock, size).decode())',
         '',
         '',
         'def run_server(once=False):',
         '    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)',
         '    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)',
         '    srv.bind((host, port))',
         '    srv.listen(5)',
         '    print("[server] listening on %s:%d" % (host, port))',
         '    while True:',
         '        conn, addr = srv.accept()',
         '        try:',
         '            msg = recv_frame(conn)',
         '            print("[server] <<REC>> received from", addr[0])',
         '            records[msg["record_id"]] = msg["envelope"]',
         '            signer_keys[msg["envelope"]["user"]] = msg["signer_key"]']
    if cfg["search"] != "NONE":
        L += ['            for token, entries in msg["index"].items():',
              '                search_index.setdefault(token, []).extend(entries)']
        if cfg["search"] == "PKSE":
            L += ['            id_of_number.update(msg["numbers"])']
    L += ['            save_all()',
          '            ok = verify_record(msg["record_id"])',
          '            send_frame(conn, {"record_id": msg["record_id"], "accepted": bool(ok)})',
          '        except Exception as exc:',
          '            send_frame(conn, {"error": str(exc)})',
          '        finally:',
          '            conn.close()',
          '        if once:',
          '            break',
          '    srv.close()',
          '',
          '',
          'def run_client(user="alice", record_id="N001", value=1, tag=101):']
    if cfg["search"] != "NONE":
        L += ['    before = {t: list(v) for t, v in search_index.items()}']
    L += ['    submit_record(user, record_id, value, tag)']
    if cfg["search"] != "NONE":
        L += ['    fresh = {t: v for t, v in search_index.items() if before.get(t) != v}']
    L += ['    sock = socket.create_connection((host, port), timeout=10)',
          '    payload = {"record_id": record_id,',
          '               "envelope": records[record_id],',
          '               "signer_key": signer_keys[user]}']
    if cfg["search"] != "NONE":
        L += ['    payload["index"] = fresh']
        if cfg["search"] == "PKSE":
            L += ['    payload["numbers"] = id_of_number']
    L += ['    send_frame(sock, payload)',
          '    print("[client] server replied:", recv_frame(sock))',
          '    sock.close()',
          '',
          '',
          'def netdemo():',
          '    # one process, two sockets: proves the client-server path really works',
          '    thread = threading.Thread(target=run_server, kwargs={"once": True}, daemon=True)',
          '    thread.start()',
          '    time.sleep(0.5)',
          '    run_client()',
          '    thread.join(timeout=5)',
          '']
    return "\n".join(L) + "\n"


# ===========================================================================
# BLOCK: menus
# ===========================================================================

def block_menu(cfg):
    L = ['def client_menu():',
         '    while True:',
         '        print("\\n<<CLIENTROLE>> MENU: 1 Submit <<REC>> | 2 View mine | 3 Back")',
         '        choice = input("Input Choice: ").strip()',
         '        if choice == "1":',
         '            user = input("User name: ").strip() or "alice"',
         '            rid = input("<<REC>> ID: ").strip() or "R001"',
         '            value = input("<<VAL>> (a number): ").strip() or "1"',
         '            tag = input("<<TAG>>: ").strip() or "101"',
         '            submit_record(user, rid, value, tag)',
         '        elif choice == "2":',
         '            view_own(input("User name: ").strip() or "alice")',
         '        elif choice == "3":',
         '            return',
         '',
         '']
    server_items = ['1 Verify <<REC>>']
    if cfg["search"] != "NONE":
        server_items.append('2 Search index')
    server_items += ['3 All <<REC>>s', '4 Tamper test', '5 Back']
    L += ['def server_menu():',
          '    while True:',
          '        print("\\n<<SERVERROLE>> MENU: ' + " | ".join(server_items) + '")',
          '        choice = input("Input Choice: ").strip()',
          '        if choice == "1":',
          '            verify_record(input("<<REC>> ID: ").strip())']
    if cfg["search"] != "NONE":
        L += ['        elif choice == "2":',
              '            print("  1 by <<TAG>>   2 by time range")',
              '            if input("  > ").strip() == "1":',
              '                hits = search_by_tag(input("<<TAG>>: ").strip())',
              '            else:',
              '                start = input("From (YYYY-MM-DD HH:MM): ").strip()',
              '                end = input("To   (YYYY-MM-DD HH:MM): ").strip()',
              '                hits = search_by_time_range(start, end)',
              '            print("Output IDs:", ", ".join(hits) or "none")']
    L += ['        elif choice == "3":',
          '            view_all()',
          '        elif choice == "4":',
          '            tamper_record(input("<<REC>> ID: ").strip())',
          '        elif choice == "5":',
          '            return',
          '',
          '']
    if cfg["he"] != "NONE":
        extra = ' | 3 One share alone' if cfg["threshold"] else ''
        L += ['def analyst_menu():',
              '    combined = None',
              '    while True:',
              '        print("\\n<<ANALYSTROLE>> MENU: 1 Aggregate | 2 Reveal total'
              + extra + ' | 4 Back")',
              '        choice = input("Input Choice: ").strip()',
              '        if choice == "1":',
              '            combined = aggregate()',
              '        elif choice == "2":',
              '            if combined is None:',
              '                print("aggregate first")',
              '            else:',
              '                reveal(combined)']
        if cfg["threshold"]:
            L += ['        elif choice == "3":',
                  '            one_share_alone()']
        L += ['        elif choice == "4":',
              '            return',
              '',
              '']
    L += ['def auditor_menu():',
          '    while True:',
          '        print("\\n<<AUDITORROLE>> MENU: 1 Hashes and signatures | 2 Audit log | 3 Back")',
          '        choice = input("Input Choice: ").strip()',
          '        if choice == "1":',
          '            show_hashes()',
          '        elif choice == "2":',
          '            show_log()',
          '        elif choice == "3":',
          '            return',
          '',
          '']
    main_items = ['1 <<CLIENTROLE>>', '2 <<SERVERROLE>>']
    if cfg["he"] != "NONE":
        main_items.append('3 <<ANALYSTROLE>>')
    main_items += ['4 <<AUDITORROLE>>', '5 Exit']
    L += ['def menu():',
          '    while True:',
          '        print("\\n" + system_name.upper())',
          '        print("MAIN MENU: ' + " | ".join(main_items) + '")',
          '        choice = input("Input Choice: ").strip()',
          '        if choice == "1":',
          '            client_menu()',
          '        elif choice == "2":',
          '            server_menu()']
    if cfg["he"] != "NONE":
        L += ['        elif choice == "3":',
              '            analyst_menu()']
    L += ['        elif choice == "4":',
          '            auditor_menu()',
          '        elif choice == "5":',
          '            print("Exit")',
          '            return',
          '        else:',
          '            print("invalid choice")',
          '']
    return "\n".join(L) + "\n"


# ===========================================================================
# BLOCK: the no-typing demonstration and the start-up code
# ===========================================================================

def block_demo(cfg):
    L = ['def demo():',
         '    print("=" * 70)',
         '    print(system_name, "- full demonstration")',
         '    print("=" * 70)',
         '',
         '    print("\\n--- CLIENT: submit three <<REC>>s ---")',
         '    submit_record("alice", "R001", 1, 101)',
         '    print()',
         '    submit_record("bob", "R002", 1, 102)',
         '    print()',
         '    submit_record("carol", "R003", 2, 101)',
         '',
         '    print("\\n--- SERVER: verify each <<REC>> ---")',
         '    for rid in ["R001", "R002", "R003"]:',
         '        print("[" + rid + "]")',
         '        verify_record(rid)',
         '        print()']
    if cfg["search"] != "NONE":
        L += ['    print("--- SERVER: searchable index (<<SEARCHNAME>>) ---")',
              '    print("<<TAG>> 101 ->", ", ".join(search_by_tag(101)))',
              '    print("<<TAG>> 102 ->", ", ".join(search_by_tag(102)))',
              '    now = datetime.now()',
              '    start = (now - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M")',
              '    end = (now + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M")',
              '    print("time range %s .. %s -> %s"',
              '          % (start, end, ", ".join(search_by_time_range(start, end))))',
              '    print("the server matched tokens; it never saw the label in the clear")',
              '']
    L += ['    print("\\n--- SERVER: tamper test ---")',
          '    tamper_record("R003")',
          '    verify_record("R003")',
          '']
    if cfg["he"] != "NONE":
        L += ['    print("\\n--- <<ANALYSTROLE>>: homomorphic aggregation ---")',
              '    combined = aggregate(["R001", "R002"])',
              '',
              '    print("\\n--- <<ANALYSTROLE>>: revealing only the total ---")',
              '    reveal(combined)']
        if cfg["threshold"]:
            L += ['    print()', '    one_share_alone()']
        L += ['']
    L += ['    print("\\n--- <<AUDITORROLE>>: integrity data only ---")',
          '    show_hashes()',
          '',
          '    print("\\n--- ACCESS CONTROL ---")',
          '    check_permission(auditor_role, "submit")',
          '    check_permission(client_role, "view_all")',
          '']
    if cfg["sockets"]:
        L += ['    print("\\n--- CLIENT-SERVER over TCP ---")',
              '    netdemo()',
              '']
    L += ['    print("\\n--- AUDIT LOG ---")',
          '    show_log()',
          '    print("\\n" + "=" * 70)',
          '    print("demonstration finished")',
          '',
          '']
    files = ['record_file', 'key_file', 'log_file']
    extra = []
    if cfg["search"] != "NONE":
        extra.append('"index.json"')
    if cfg["search"] == "PKSE":
        extra += ['"pkse_key.json"', '"numbers.json"']
    if cfg["he"] != "NONE":
        extra.append('"he_key.json"')
    if cfg["wrap"] != "NONE":
        extra += ['"server_private.pem"', '"server_public.pem"']
    L += ['def reset():',
          '    for path in [' + ", ".join(files + extra) + ']:',
          '        try:',
          '            if os.path.exists(path):',
          '                os.remove(path)',
          '        except OSError:',
          '            pass            # Windows keeps a handle open now and then',
          '    print("stored files removed")',
          '']
    return "\n".join(L) + "\n"


def block_startup(cfg):
    L = ['if len(sys.argv) > 1 and sys.argv[1] == "reset":',
         '    reset()',
         '    sys.exit(0)',
         '',
         'load_all()']
    if cfg["search"] == "SSE":
        L += ['index_key = hashlib.sha256((system_name + "-index").encode()).digest()[:key_bytes]']
    if cfg["search"] == "PKSE":
        L += ['pkse_key = pkse_keygen()']
    L += ['server_private, server_public = server_keys()']
    if cfg["he"] != "NONE":
        L += ['he_pub = he_keygen()',
              'he_secret = he_pub.pop("secret")      # the piece that must stay private']
    L += ['',
          'if __name__ == "__main__":',
          '    arg = sys.argv[1] if len(sys.argv) > 1 else ""',
          '    if arg == "demo":',
          '        demo()']
    if cfg["sockets"]:
        L += ['    elif arg == "netdemo":',
              '        netdemo()',
              '    elif arg == "server":',
              '        run_server()',
              '    elif arg == "client":',
              '        run_client(*sys.argv[2:])']
    L += ['    else:',
          '        menu()',
          '']
    return "\n".join(L) + "\n"


# ===========================================================================
# ASSEMBLY
# ===========================================================================

def role_named(cfg, action, fallback):
    for role, actions in cfg["roles"].items():
        if action in actions:
            return role
    return fallback


def build_source(cfg):
    parts = [block_head(cfg)]

    roles_const = ['client_role = "%s"' % role_named(cfg, "submit", "client"),
                   'server_role = "%s"' % role_named(cfg, "verify", "server")]
    if cfg["he"] != "NONE":
        roles_const.append('analyst_role = "%s"' % role_named(cfg, "aggregate", "analyst"))
    roles_const.append('auditor_role = "%s"' % role_named(cfg, "view_hashes", "auditor"))
    parts.append("\n".join(roles_const) + "\n")

    parts.append(banner("Small helpers") + BLOCK_HELPERS)
    parts.append(banner("Encryption and decryption (ED)"))
    parts.append(NEW_KEY_DES3 if cfg["cipher"] == "3DES" else NEW_KEY_PLAIN)
    parts.append(ED_BODIES[cfg["mode"]])
    parts.append(banner("Wrapping the session key with a public key"))
    parts.append({"RSA": WRAP_RSA, "ECC": WRAP_ECC, "NONE": WRAP_NONE}[cfg["wrap"]])
    parts.append(banner("Hashing (Hash)") + BLOCK_HASH)
    parts.append(banner("Digital signature (DSS)") + SIGN_BLOCKS[cfg["sign"]])
    if cfg["he"] != "NONE":
        parts.append(banner("Partial homomorphic encryption") + HE_BLOCKS[cfg["he"]])
    if cfg["threshold"] and cfg["he"] != "NONE":
        parts.append(banner("Threshold decryption") + BLOCK_THRESHOLD)
    if cfg["search"] != "NONE":
        parts.append(banner("Searchable encryption (Search)"))
        parts.append(SEARCH_SSE if cfg["search"] == "SSE" else SEARCH_PKSE)
        parts.append(SEARCH_COMMON)
    parts.append(banner("Audit log") + BLOCK_AUDIT)

    save_extra, load_globals, load_extra = "", "", ""
    if cfg["search"] != "NONE":
        save_extra = '    json.dump(search_index, open("index.json", "w"), indent=2)\n'
        load_globals += ", search_index"
        load_extra = ('    if os.path.exists("index.json"):\n'
                      '        search_index = json.load(open("index.json"))\n')
    if cfg["search"] == "PKSE":
        save_extra += '    json.dump(id_of_number, open("numbers.json", "w"), indent=2)\n'
        load_globals += ", id_of_number"
        load_extra += ('    if os.path.exists("numbers.json"):\n'
                       '        id_of_number = json.load(open("numbers.json"))\n')
    store = (BLOCK_STORE.replace("<<SAVE_EXTRA>>", save_extra.rstrip("\n"))
             .replace("<<LOAD_GLOBALS>>", load_globals)
             .replace("<<LOAD_EXTRA>>", load_extra.rstrip("\n")))
    parts.append(banner("Saving and loading") + store)
    parts.append(banner("Access control") + BLOCK_RBAC)
    parts.append(banner("Client side: build and submit") + "\n" + block_client(cfg))
    parts.append(banner("Server side: verify") + "\n" + block_server(cfg))
    agg = block_agg(cfg)
    if agg:
        parts.append(banner("Aggregation and reveal") + "\n" + agg)
    parts.append(banner("Views") + BLOCK_VIEWS)
    net = block_net(cfg)
    if net:
        parts.append(banner("Client-Server over TCP") + "\n" + net)
    parts.append(banner("Menus") + "\n" + block_menu(cfg))
    parts.append(banner("Full run with no typing") + "\n" + block_demo(cfg))
    parts.append(banner("Start up") + "\n" + block_startup(cfg))

    text = "\n".join(parts)
    text = text.replace("<<SIGNNAME>>", SIGN_LABEL[cfg["sign"]])
    text = text.replace("<<WRAPNAME>>", cfg["wrap"] + "-" + str(cfg["rsa_bits"])
                        if cfg["wrap"] == "RSA" else "<<WRAPNAME>>")
    text = text.replace("<<WRAPNAME>>", "ECC P-256" if cfg["wrap"] == "ECC" else "the shared key")
    text = text.replace("<<SEARCHNAME>>", cfg["search"])
    text = text.replace("<<CLIENTROLE>>", role_named(cfg, "submit", "client").upper())
    text = text.replace("<<SERVERROLE>>", role_named(cfg, "verify", "server").upper())
    text = text.replace("<<ANALYSTROLE>>", role_named(cfg, "aggregate", "analyst").upper())
    text = text.replace("<<AUDITORROLE>>", role_named(cfg, "view_hashes", "auditor").upper())
    text = text.replace("<<OUT>>", cfg["out"])
    text = fill(text, cfg)
    text = re.sub(r"\n{4,}", "\n\n\n", text)
    return text.rstrip("\n") + "\n"


# ===========================================================================
# WRITING THE TWO OUTPUT FILES
# ===========================================================================

def strip_comments(source):
    # Removes the teaching comments but KEEPS the section banners, so the
    # clean file still reads like a structured answer.
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
    except tokenize.TokenError:
        return source
    out = []
    last_row, last_col = -1, 0
    for tok in tokens:
        srow, scol = tok.start
        if srow > last_row:
            last_col = 0
        if scol > last_col:
            out.append(" " * (scol - last_col))
        if tok.type == tokenize.COMMENT and not tok.string.startswith(("# ----------", "# =====")):
            pass                        # drop this comment, keep its newline token
        else:
            out.append(tok.string)
        last_row, last_col = tok.end
    lines = [line.rstrip() for line in "".join(out).split("\n")]
    cleaned, blanks = [], 0
    for line in lines:
        if line.strip() == "":
            blanks += 1
            if blanks > 2:
                continue
        else:
            blanks = 0
        cleaned.append(line)
    return "\n".join(cleaned).strip("\n") + "\n"


def write_pair(cfg, quiet=False):
    source = build_source(cfg)
    main_path = cfg["out"] + ".py"
    clean_path = cfg["out"] + "_clean.py"

    ast.parse(source)                   # fail loudly here, not in the exam
    open(main_path, "w", encoding="utf-8").write(source)

    try:
        clean = strip_comments(source)
        ast.parse(clean)
    except Exception:
        clean = source                  # never hand over a broken file
    open(clean_path, "w", encoding="utf-8").write(clean)

    if not quiet:
        print()
        print("written:", main_path, "(%d lines, with comments)" % source.count("\n"))
        print("written:", clean_path, "(%d lines, comments stripped)" % clean.count("\n"))
        print()
        print("NEXT:")
        print("   python %s demo        full run, no typing" % main_path)
        print("   python %s             the menu  <- show this to the examiner" % main_path)
        print("   python %s reset       clear the stored files" % main_path)
    return main_path, clean_path


# ===========================================================================
# THE WIZARD
# ===========================================================================

def ask(prompt, default, options=None):
    if options:
        print("   options:", " / ".join(str(o) for o in options))
    answer = input("%s [%s]: " % (prompt, default)).strip()
    if not answer:
        return default
    if options:
        match = [o for o in options if str(o).lower() == answer.lower()]
        if match:
            return match[0]
        print("   not one of the options, keeping", default)
        return default
    return answer


def ask_yes(prompt, default):
    answer = input("%s [%s]: " % (prompt, "y" if default else "n")).strip().lower()
    if not answer:
        return default
    return answer.startswith("y")


def wizard():
    print("=" * 72)
    print(" endsheet.py - end-sem answer writer   (press Enter to accept [default])")
    print("=" * 72)
    print()
    print(" Which scenario is the question closest to?")
    for name, preset in PRESETS.items():
        print("   %-11s %s" % (name, preset["_about"]))
    print("   %-11s %s" % ("custom", "start from the defaults and set everything"))
    choice = ask(" scenario", "evoting", list(PRESETS) + ["custom"])

    cfg = dict(DEFAULTS)
    cfg["roles"] = dict(DEFAULTS["roles"])
    if choice in PRESETS:
        for key, value in PRESETS[choice].items():
            if key != "_about":
                cfg[key] = value
        cfg["roles"] = dict(cfg["roles"])

    print()
    print("--- what the system is called ---")
    cfg["system_name"] = ask(" system name", cfg["system_name"])
    cfg["record_word"] = ask(" what is one stored item called", cfg["record_word"])
    cfg["tag_word"] = ask(" the field you search on", cfg["tag_word"])
    cfg["value_word"] = ask(" the numeric field that gets totalled", cfg["value_word"])

    print()
    print("--- ED: encryption ---")
    cfg["cipher"] = ask(" symmetric cipher", cfg["cipher"], list(CIPHER_INFO))
    cfg["mode"] = ask(" mode of operation", cfg["mode"], MODES)
    cfg["wrap"] = ask(" how is the session key sent", cfg["wrap"], WRAPS)
    if cfg["wrap"] == "RSA":
        cfg["rsa_bits"] = int(ask(" RSA key size", cfg["rsa_bits"], [1024, 2048, 3072, 4096]))

    print()
    print("--- Hash and DSS ---")
    cfg["hash"] = ask(" hash algorithm", cfg["hash"], list(HASH_INFO))
    cfg["sign"] = ask(" signature scheme", cfg["sign"], SIGNS)

    print()
    print("--- Lab 7 and Lab 8 ---")
    cfg["he"] = ask(" homomorphic scheme", cfg["he"], HES)
    if cfg["he"] != "NONE":
        cfg["threshold"] = ask_yes(" threshold decryption of the total", cfg["threshold"])
        if cfg["threshold"]:
            cfg["threshold_t"] = int(ask(" shares needed", cfg["threshold_t"]))
            cfg["threshold_n"] = int(ask(" shares handed out", cfg["threshold_n"]))
    else:
        cfg["threshold"] = False
    cfg["search"] = ask(" searchable encryption", cfg["search"], SEARCHES)

    print()
    print("--- the rest ---")
    cfg["timestamps"] = ask_yes(" trusted timestamps and a deadline check", cfg["timestamps"])
    cfg["sockets"] = ask_yes(" real TCP client and server", cfg["sockets"])

    print()
    print("--- roles ---")
    print(" current roles:")
    for role, actions in cfg["roles"].items():
        print("   %-12s %s" % (role, ", ".join(actions)))
    if ask_yes(" rename the roles", False):
        new_roles = {}
        for role, actions in cfg["roles"].items():
            new_name = ask("   name for the role that can " + actions[0], role)
            new_roles[new_name] = actions
        cfg["roles"] = new_roles

    cfg["out"] = ask("\n output file name (no .py)", cfg["out"])

    print()
    print("--- building ---")
    describe(cfg)
    return write_pair(cfg)


def describe(cfg):
    print("  system      :", cfg["system_name"])
    print("  ED          :", cfg["cipher"], "/", cfg["mode"], "| key wrap:", cfg["wrap"])
    print("  Hash        :", cfg["hash"])
    print("  DSS         :", SIGN_LABEL[cfg["sign"]])
    print("  Lab 7       :", HE_LABEL[cfg["he"]] or "not used")
    print("  Lab 8       :", cfg["search"] if cfg["search"] != "NONE" else "not used")
    print("  threshold   :", "%d of %d" % (cfg["threshold_t"], cfg["threshold_n"])
          if cfg["threshold"] and cfg["he"] != "NONE" else "not used")
    print("  timestamps  :", "yes" if cfg["timestamps"] else "no")
    print("  client-server:", "TCP sockets" if cfg["sockets"] else "in one process")
    print("  roles       :", ", ".join(cfg["roles"]))


# ===========================================================================
# CHECK, PRESETS, OPTIONS, SELF TEST
# ===========================================================================

def native_modules_blocked():
    """True when this machine refuses to load pycryptodome's compiled parts.

    Some Windows machines run an Application Control policy that blocks
    unsigned native libraries. When that happens the answer file needs one
    extra line to load the pure-Python fallback from pylib/, so the build
    checks here and emits it only where it is needed.
    """
    try:
        import islab_compat
        # the fallback is already active in THIS process, which only happens
        # on a machine where the native modules were refused
        return islab_compat.MODE == "pure"
    except ImportError:
        pass
    try:
        import Crypto.Cipher.AES                            # noqa: F401
        import Crypto.Hash.SHA256                           # noqa: F401
        return False
    except Exception:
        return True


def check():
    print("python     :", sys.version.split()[0], "-", sys.executable)
    ok = True
    try:
        import Crypto
        print("pycryptodome:", Crypto.__version__)
    except ImportError:
        print("pycryptodome: MISSING  ->  pip install pycryptodome")
        ok = False
    try:
        import islab_compat
        print("backend    :", islab_compat.status())
    except ImportError:
        if native_modules_blocked():
            print("backend    : native modules are BLOCKED and pylib/ was not"
                  " found - run this through ../../wizard.py")
            ok = False
        else:
            print("backend    : pycryptodome native modules: OK")
    for module in ["hashlib", "hmac", "socket", "json", "random"]:
        try:
            __import__(module)
        except ImportError:
            print(module, ": MISSING")
            ok = False
    print("stdlib     : ok")
    print()
    print("ENVIRONMENT READY" if ok else "FIX THE MISSING PIECES FIRST")
    return ok


def show_presets():
    print("ready-made scenarios  ->  --build NAME")
    for name, preset in PRESETS.items():
        print("  %-11s %s" % (name, preset["_about"]))


def show_options():
    print("every value each setting accepts")
    print("  cipher     :", ", ".join(CIPHER_INFO))
    print("  mode       :", ", ".join(MODES))
    print("  key wrap   :", ", ".join(WRAPS))
    print("  hash       :", ", ".join(HASH_INFO))
    print("  signature  :", ", ".join(SIGNS))
    print("  homomorphic:", ", ".join(HES))
    print("  search     :", ", ".join(SEARCHES))
    print("  threshold  : on / off      timestamps: on / off    sockets: on / off")
    print()
    total = (len(CIPHER_INFO) * len(MODES) * len(WRAPS) * len(HASH_INFO)
             * len(SIGNS) * len(HES) * len(SEARCHES) * 2 * 2 * 2)
    print("  that is %d different answer files this one script can write" % total)


def selftest(limit=None):
    import shutil
    import tempfile

    # the generated files are run from a scratch folder, so point the child
    # processes at this project root, where islab.py and pylib/ live
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))
    child_env = dict(os.environ)
    child_env["PYTHONPATH"] = os.pathsep.join(
        [p for p in (project_root, os.path.join(project_root, "pylib"),
                     child_env.get("PYTHONPATH", "")) if p])

    cases = []
    base = dict(DEFAULTS)
    for name in PRESETS:
        cfg = dict(base)
        cfg["roles"] = dict(base["roles"])
        for key, value in PRESETS[name].items():
            if key != "_about":
                cfg[key] = value
        cases.append(("preset " + name, cfg))

    def variant(label, **changes):
        cfg = dict(base)
        cfg["roles"] = dict(base["roles"])
        cfg.update(changes)
        cases.append((label, cfg))

    for mode in MODES:
        variant("mode " + mode, mode=mode)
    for cipher in CIPHER_INFO:
        variant("cipher " + cipher, cipher=cipher)
    for scheme in SIGNS:
        variant("sign " + scheme, sign=scheme)
    for algo in HASH_INFO:
        variant("hash " + algo, hash=algo)
    for he in HES:
        variant("he " + he, he=he)
    for search in SEARCHES:
        variant("search " + search, search=search)
    for wrap in WRAPS:
        variant("wrap " + wrap, wrap=wrap)
    variant("no threshold", threshold=False)
    variant("no timestamps", timestamps=False)
    variant("no sockets", sockets=False)
    variant("bare minimum", he="NONE", search="NONE", wrap="NONE",
            threshold=False, timestamps=False, sockets=False)
    variant("everything on", he="PAILLIER", search="SSE", wrap="RSA",
            threshold=True, timestamps=True, sockets=True, sign="SCHNORR",
            cipher="3DES", mode="CTR", hash="md5")

    if limit:
        cases = cases[:limit]

    passed, failed = 0, []
    print("SELF TEST : %d configurations, each built, parsed and run" % len(cases))
    print("-" * 72)
    for label, cfg in cases:
        cfg = dict(cfg)
        cfg["out"] = "answer"
        work = tempfile.mkdtemp(prefix="endsheet_")
        here = os.getcwd()
        try:
            os.chdir(work)
            main_path, clean_path = write_pair(cfg, quiet=True)
            for path in (main_path, clean_path):
                result = subprocess.run([sys.executable, path, "demo"],
                                        capture_output=True, text=True,
                                        timeout=300, env=child_env)
                output = result.stdout + result.stderr
                if result.returncode != 0 or "demonstration finished" not in output:
                    raise AssertionError("%s: %s" % (
                        path, output.strip().split("\n")[-1] if output.strip() else "no output"))
                if "Traceback" in output:
                    raise AssertionError(path + ": traceback in output")
            passed += 1
            print("  ok    %s" % label)
        except Exception as exc:
            failed.append((label, str(exc)))
            print("  FAIL  %-22s %s" % (label, str(exc)[:70]))
        finally:
            os.chdir(here)
            shutil.rmtree(work, ignore_errors=True)
    print("-" * 72)
    print("%d/%d passed" % (passed, len(cases)))
    for label, why in failed:
        print("  FAILED:", label, "->", why[:200])
    return not failed


def build_preset(name):
    if name not in PRESETS:
        print("unknown preset:", name)
        show_presets()
        return
    cfg = dict(DEFAULTS)
    cfg["roles"] = dict(DEFAULTS["roles"])
    for key, value in PRESETS[name].items():
        if key != "_about":
            cfg[key] = value
    print("building preset:", name, "-", PRESETS[name]["_about"])
    describe(cfg)
    write_pair(cfg)


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        return
    flag = args[0]
    if flag == "--check":
        check()
    elif flag == "--presets":
        show_presets()
    elif flag == "--options":
        show_options()
    elif flag == "--wizard":
        wizard()
    elif flag == "--build":
        build_preset(args[1] if len(args) > 1 else "evoting")
    elif flag == "--selftest":
        limit = int(args[1]) if len(args) > 1 else None
        sys.exit(0 if selftest(limit) else 1)
    else:
        print("unknown option:", flag)
        print(__doc__)


if __name__ == "__main__":
    main()
