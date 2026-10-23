r"""
===============================================================================
  INFORMATION SECURITY LAB - PLAYSHEET
  Answers Lab 1-6 of the manual. Nothing you hand in imports from this file.
===============================================================================

  BEFORE THE EXAM (internet is still on)
  --------------------------------------
      python -m venv .venv                     make an isolated environment
      .venv\Scripts\activate                   Windows     (source .venv/bin/activate on mac/linux)
      python playsheet.py --setup              installs pycryptodome
      python playsheet.py --check              wants RESULT: READY
      python playsheet.py --selftest           wants 113/113 passed

  DURING THE EXAM
  ---------------
      python playsheet.py --wizard             9 questions -> a finished answer file
      python answer.py demo                    full walkthrough, no typing
      python answer.py                         the menu, for the examiner

  EVERY BUILD WRITES TWO FILES
  ----------------------------
    answer.py        every comment kept - this is the one you read and learn
                     from, and the one to reconfigure
    answer_clean.py  the same behaviour with the explanatory comments and
                     docstrings removed. The # ---------- Section ----------
                     banners and the SETTINGS markers are kept, so it still
                     reads as a finished submission rather than a wall of
                     functions. Both are verified to run identically.

  ANSWERS ARE PRINTED IN HEXADECIMAL
  ----------------------------------
    Ciphertext, hashes and signatures all print as hex. Big numbers (ElGamal
    and Schnorr signatures) are stored and shown in hex instead of enormous
    decimal strings. A classical cipher still shows its letters, because that
    IS the answer, with the hex on the line underneath.

  TWO SIZES OF OUTPUT
  -------------------
    LEAN (the default)   ~387 lines, ~359 without comments. Contains ONLY
                         the cipher, hash and signature scheme you chose,
                         plus the role-based system. This is what you want
                         in an exam.
    FULL (--full)        ~1300 lines. Pastes whole libraries: every cipher,
                         every signature scheme, sockets, key management.
                         Use it when the question asks for the extras.

  HOW THE LEAN FILE IS WRITTEN
  ----------------------------
    Flat and plain, the way a lab answer is actually handed in:
      - top-to-bottom functions, no class wrapping the program
      - a SETTINGS block of ordinary variables at the top
      - ordinary print("Label     :", value) output, no helper layer
      - sections marked with  # ---------- Hashing ----------
    Change the key or the roles in SETTINGS; change the cipher, hash or
    signature scheme with --reconfigure.

      python playsheet.py --wizard                 lean
      python playsheet.py --wizard --full          full
      python playsheet.py --lean AES-256 -o answer.py     no questions at all
      python playsheet.py --compare                shows the size difference

  Every build also writes <name>_clean.py - see above.

  BLOCK INDEX (for --build and for copy-paste)        paste after
  -------------------------------------------------   -----------
    CORE               helpers, maths, key handling    (always first)
    CLASSIC_SUB        additive / multiplicative / affine       CORE
    CLASSIC_POLY       Vigenere / autokey                       CORE
    CLASSIC_PLAYFAIR   Playfair                                 CORE
    CLASSIC_HILL       Hill (any n x n)                         CORE
    CLASSIC_TRANS      columnar + rail fence transposition      CORE
    SYM                DES / 3DES / AES + ECB CBC CFB OFB CTR   CORE
    AESSTEPS           AES key expansion + round keys shown     CORE + SYM
    RSA                RSA textbook + 2048-bit + hybrid         CORE
    PERF               RSA vs ECC timing comparison             CORE + RSA
    ELGAMAL            ElGamal encryption                       CORE
    RABIN              Rabin encryption                         CORE
    DH                 Diffie-Hellman                           CORE
    ECC                ECC / ECDH hybrid                        CORE
    HASH               custom djb2 + MD5..SHA-512 + HMAC        CORE
    SIGN               RSA / ECDSA / ElGamal / Schnorr / raw     CORE + RSA(+ECC)
    KMS                key generate/distribute/revoke/renew     CORE + SYM
    ACCESS             RBAC ABAC Bell-LaPadula MAC DAC time     CORE
    SOCKET             client-server integrity + signature      CORE + HASH
    ATTACK             brute force / known-plaintext / Fermat   CORE
    DISPATCH           makes EVERY cipher interchangeable       CORE + ciphers
    TEMPLATE           menu-driven role-based scenario system   CORE + DISPATCH

  PRESETS FOR --build
  -------------------
    exam       the DES/AES scenario system (full size)
    classical  same, with every classical cipher included
    network    sockets: client-server integrity and signatures
    keymgmt    key management service + access control
    lab1 .. lab6   exactly the blocks that lab of the manual needs

  MANUAL COVERAGE
  ---------------
    Lab 1  additive multiplicative affine Vigenere autokey Playfair Hill
           columnar + rail fence transposition, brute force / known-plaintext
    Lab 2  DES 3DES AES-128/192/256, ECB CBC CFB OFB CTR, timing comparison,
           AES key expansion printed round by round
    Lab 3  RSA (textbook + 2048), ECC/ECIES, ElGamal, Diffie-Hellman,
           RSA vs ECC performance comparison
    Lab 4  Rabin, key management (generate/distribute/revoke/renew/store/log),
           RBAC ABAC Bell-LaPadula DAC time-based, weak-RSA attacks
           (trial division, Fermat close-primes, shared prime)
    Lab 5  custom djb2 hash, MD5/SHA-1/SHA-256 timing, collision detection
           on truncated digests, socket integrity + multi-part reassembly
    Lab 6  RSA / ECDSA / ElGamal / Schnorr signatures, raw "textbook" RSA in
           the manual's 0x-hex format, client-server verification, CIA triad
===============================================================================
"""

# >>>>> BLOCK: CORE >>>>>
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
    """Accept raw text, bytes, OR a filename - returns bytes either way."""
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
    """Interactive: types text OR gives a filename - both work."""
    raw = input(prompt).strip()
    if os.path.isfile(raw):
        print("  [reading file:", raw + "]")
    return read_input(raw), raw


def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# A Windows console defaults to cp1252 and raises UnicodeEncodeError on any
# character it cannot map - which is exactly what a tampered record produces.
try:
    sys.stdout.reconfigure(errors="replace")
except Exception:
    pass


def safe_text(data):
    """bytes or str -> something the console can definitely print.

    Real text is shown as-is; bytes that are not valid text (a tampered
    record) come back with every unprintable byte as a dot."""
    if isinstance(data, bytes):
        try:
            data = data.decode("utf-8")
        except UnicodeDecodeError:
            return "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    enc = getattr(sys.stdout, "encoding", None) or "ascii"
    return str(data).encode(enc, "replace").decode(enc, "replace")


def hexs(value, group=0):
    """Render ANY answer as hexadecimal.

    int   -> even-length hex, e.g. 4660 becomes '1234'
    bytes -> the usual .hex()
    str   -> hex of its UTF-8 bytes
    list/tuple of ints -> each one in hex, comma separated
    group=n inserts a space every n hex digits so long values stay readable.
    """
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
    """Read a hex string back as an integer (the inverse of hexs for ints)."""
    return int(str(text).replace(" ", ""), 16)


def show(label, value, width=18):
    print(str(label).ljust(width), ":", value)


def preview(data, n=64):
    s = data.hex() if isinstance(data, (bytes, bytearray)) else str(data)
    return s if len(s) <= n else s[:n] + "..."


def clean_text(text, merge_j=False):
    """Uppercase A-Z only (classical ciphers need this)."""
    if isinstance(text, (bytes, bytearray)):
        text = text.decode(errors="ignore")
    t = "".join(c for c in str(text).upper() if c.isalpha())
    return t.replace("J", "I") if merge_j else t


# --- modular arithmetic ------------------------------------------------------
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
    """Any key (text / hex / bytes) -> exactly `size` bytes.
    'A1B2C3D4'(8 chars)->DES ascii ; 32-hex-chars->AES-128 hex ; else padded."""
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
# <<<<< END BLOCK: CORE <<<<<


# >>>>> BLOCK: CLASSIC_SUB >>>>>
# ============ ADDITIVE / MULTIPLICATIVE / AFFINE  (Lab 1 Q1) =================
def additive_encrypt(text, key):
    return "".join(chr((ord(c) - 65 + int(key)) % 26 + 65)
                   for c in clean_text(text))


def additive_decrypt(cipher, key):
    return "".join(chr((ord(c) - 65 - int(key)) % 26 + 65)
                   for c in clean_text(cipher))


def multiplicative_encrypt(text, key):
    return "".join(chr(((ord(c) - 65) * int(key)) % 26 + 65)
                   for c in clean_text(text))


def multiplicative_decrypt(cipher, key):
    inv = modinv(int(key), 26)
    if inv is None:
        raise ValueError("key %s has no inverse mod 26" % key)
    return "".join(chr(((ord(c) - 65) * inv) % 26 + 65)
                   for c in clean_text(cipher))


def affine_encrypt(text, a, b):
    return "".join(chr((int(a) * (ord(c) - 65) + int(b)) % 26 + 65)
                   for c in clean_text(text))


def affine_decrypt(cipher, a, b):
    inv = modinv(int(a), 26)
    if inv is None:
        raise ValueError("a=%s has no inverse mod 26" % a)
    return "".join(chr((inv * (ord(c) - 65 - int(b))) % 26 + 65)
                   for c in clean_text(cipher))
# <<<<< END BLOCK: CLASSIC_SUB <<<<<


# >>>>> BLOCK: CLASSIC_POLY >>>>>
# ==================== VIGENERE / AUTOKEY  (Lab 1 Q2) ========================
def vigenere_encrypt(text, key):
    t, k = clean_text(text), clean_text(key)
    return "".join(chr((ord(c) - 65 + ord(k[i % len(k)]) - 65) % 26 + 65)
                   for i, c in enumerate(t))


def vigenere_decrypt(cipher, key):
    t, k = clean_text(cipher), clean_text(key)
    return "".join(chr((ord(c) - 65 - (ord(k[i % len(k)]) - 65)) % 26 + 65)
                   for i, c in enumerate(t))


def _autokey_seed(key):
    """Accepts 7, '7' or a keyword like 'HEALTH'."""
    if isinstance(key, int):
        return [key]
    s = str(key)
    if s.isdigit():
        return [int(s)]
    return [ord(c) - 65 for c in clean_text(s)]


def autokey_encrypt(text, key):
    t = clean_text(text)
    stream = _autokey_seed(key) + [ord(c) - 65 for c in t]
    return "".join(chr((ord(c) - 65 + stream[i]) % 26 + 65)
                   for i, c in enumerate(t))


def autokey_decrypt(cipher, key):
    t = clean_text(cipher)
    stream, out = list(_autokey_seed(key)), ""
    for i, c in enumerate(t):
        p = (ord(c) - 65 - stream[i]) % 26
        out += chr(p + 65)
        stream.append(p)
    return out
# <<<<< END BLOCK: CLASSIC_POLY <<<<<


# >>>>> BLOCK: CLASSIC_PLAYFAIR >>>>>
# ========================= PLAYFAIR  (Lab 1 Q3) =============================
def playfair_matrix(key):
    seen, mat = set(), []
    for ch in clean_text(key, merge_j=True) + "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if ch not in seen and ch != "J":
            seen.add(ch)
            mat.append(ch)
    return [mat[i:i + 5] for i in range(0, 25, 5)]


def _pf_pos(matrix, ch):
    for i in range(5):
        for j in range(5):
            if matrix[i][j] == ch:
                return i, j
    raise ValueError("letter %s not in matrix" % ch)


def playfair_pairs(text, filler="X"):
    t = clean_text(text, merge_j=True)
    out, i = [], 0
    while i < len(t):
        a = t[i]
        b = t[i + 1] if i + 1 < len(t) else filler
        if a == b:
            out.append(a + filler)
            i += 1
        else:
            out.append(a + b)
            i += 2
    return out


def _playfair_run(text, key, step):
    matrix = playfair_matrix(key)
    if step == 1:
        pairs = playfair_pairs(text)
    else:
        t = clean_text(text, merge_j=True)
        pairs = [t[i:i + 2] for i in range(0, len(t), 2)]
    out = ""
    for pr in pairs:
        r1, c1 = _pf_pos(matrix, pr[0])
        r2, c2 = _pf_pos(matrix, pr[1])
        if r1 == r2:
            out += matrix[r1][(c1 + step) % 5] + matrix[r2][(c2 + step) % 5]
        elif c1 == c2:
            out += matrix[(r1 + step) % 5][c1] + matrix[(r2 + step) % 5][c2]
        else:
            out += matrix[r1][c2] + matrix[r2][c1]
    return out


def playfair_encrypt(text, key):
    return _playfair_run(text, key, 1)


def playfair_decrypt(cipher, key):
    return _playfair_run(cipher, key, -1)


def print_playfair_matrix(key):
    for row in playfair_matrix(key):
        print("   ", " ".join(row))
# <<<<< END BLOCK: CLASSIC_PLAYFAIR <<<<<


# >>>>> BLOCK: CLASSIC_HILL >>>>>
# ===================== HILL CIPHER, any n x n  (Lab 1 Q4) ===================
def mat_minor(m, i, j):
    return [row[:j] + row[j + 1:] for k, row in enumerate(m) if k != i]


def mat_det(m, mod):
    n = len(m)
    if n == 1:
        return m[0][0] % mod
    if n == 2:
        return (m[0][0] * m[1][1] - m[0][1] * m[1][0]) % mod
    return sum(((-1) ** j) * m[0][j] * mat_det(mat_minor(m, 0, j), mod)
               for j in range(n)) % mod


def mat_inv_mod(m, mod=26):
    """Matrix inverse mod 26 - needed for Hill DECRYPTION."""
    n = len(m)
    di = modinv(mat_det(m, mod), mod)
    if di is None:
        return None
    if n == 1:
        return [[di]]
    cof = [[((-1) ** (i + j)) * mat_det(mat_minor(m, i, j), mod)
            for j in range(n)] for i in range(n)]
    adj = [[cof[j][i] % mod for j in range(n)] for i in range(n)]
    return [[(di * adj[i][j]) % mod for j in range(n)] for i in range(n)]


def hill_encrypt(text, key, filler="X"):
    n = len(key)
    t = clean_text(text)
    while len(t) % n:
        t += filler
    out = ""
    for i in range(0, len(t), n):
        blk = [ord(c) - 65 for c in t[i:i + n]]
        for r in range(n):
            out += chr(sum(key[r][c] * blk[c] for c in range(n)) % 26 + 65)
    return out


def hill_decrypt(cipher, key):
    inv = mat_inv_mod(key, 26)
    if inv is None:
        raise ValueError("Hill key is not invertible mod 26")
    return hill_encrypt(cipher, inv)
# <<<<< END BLOCK: CLASSIC_HILL <<<<<


# >>>>> BLOCK: CLASSIC_TRANS >>>>>
# ================= KEYED COLUMNAR TRANSPOSITION  (Lab 1) ====================
def _col_order(key):
    s = str(key)
    if s.isdigit():
        return [int(d) - 1 for d in s]
    ks = clean_text(s)
    return [i for i, _ in sorted(enumerate(ks), key=lambda p: (p[1], p[0]))]


def transposition_encrypt(text, key):
    t = clean_text(text)
    order = _col_order(key)
    n = len(order)
    while len(t) % n:
        t += "X"
    rows = [t[i:i + n] for i in range(0, len(t), n)]
    return "".join("".join(r[c] for r in rows) for c in order)


def transposition_decrypt(cipher, key):
    t = clean_text(cipher)
    order = _col_order(key)
    n = len(order)
    rows_n = len(t) // n
    cols, idx = {}, 0
    for c in order:
        cols[c] = t[idx:idx + rows_n]
        idx += rows_n
    return "".join("".join(cols[c][r] for c in range(n)) for r in range(rows_n))


# --- keyless transposition (rail fence) - manual Lab 1 concept --------------
def rail_fence_encrypt(text, rails=3):
    """Zig-zag down and up the rails, then read the rails off in order."""
    t = clean_text(text)
    rows = [""] * rails
    r, step = 0, 1
    for ch in t:
        rows[r] += ch
        if r == 0:
            step = 1
        elif r == rails - 1:
            step = -1
        r += step
    return "".join(rows)


def rail_fence_decrypt(cipher, rails=3):
    """Rebuild the zig-zag pattern, then refill it rail by rail."""
    n = len(cipher)
    pattern, r, step = [], 0, 1
    for _ in range(n):
        pattern.append(r)
        if r == 0:
            step = 1
        elif r == rails - 1:
            step = -1
        r += step
    out, i = [""] * n, 0
    for rail in range(rails):
        for pos in range(n):
            if pattern[pos] == rail:
                out[pos] = cipher[i]
                i += 1
    return "".join(out)
# <<<<< END BLOCK: CLASSIC_TRANS <<<<<


# >>>>> BLOCK: SYM >>>>>
# ===== DES / 3DES / AES-128/192/256  x  ECB CBC CFB OFB CTR GCM  (Lab 2) ====
# needs: CORE      pip install pycryptodome
from Crypto.Cipher import DES, DES3, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

SYM_ALGOS = {"DES": (DES, 8), "3DES": (DES3, 24), "AES-128": (AES, 16),
             "AES-192": (AES, 24), "AES-256": (AES, 32)}
BLOCK_MODES = ("ECB", "CBC")            # need padding
STREAM_MODES = ("CFB", "OFB", "CTR")    # no padding


def _fix_3des_key(k):
    """3DES rejects keys whose halves repeat; re-derive deterministically."""
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
    """data may be text, bytes OR a filename.  Returns (ciphertext, iv)."""
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
    """Authenticated encryption: returns (ciphertext, nonce, tag)."""
    nonce = nonce or get_random_bytes(12)
    c = AES.new(make_key(key, 32), AES.MODE_GCM, nonce=nonce)
    ct, tag = c.encrypt_and_digest(read_input(data))
    return ct, nonce, tag


def aes_gcm_decrypt(ciphertext, key, nonce, tag):
    c = AES.new(make_key(key, 32), AES.MODE_GCM, nonce=nonce)
    return c.decrypt_and_verify(ciphertext, tag)      # raises if tampered


def encrypt_file(infile, outfile, key, algo="AES-256", mode="CBC"):
    """IV is stored as a prefix of the output file."""
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
# <<<<< END BLOCK: SYM <<<<<


# >>>>> BLOCK: AESSTEPS >>>>>
# ===== AES KEY EXPANSION, SHOWN STEP BY STEP  (Lab 2 Q5) ====================
#  "Show all the steps involved in the encryption process (key expansion,
#   initial round, main rounds, final round)."  needs: CORE + SYM
# ===========================================================================
AES_SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16]

AES_RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,
            0x1b,0x36,0x6c,0xd8,0xab,0x4d]


def aes_key_expansion(key_bytes):
    """Return (list_of_4_byte_words, number_of_rounds).

    Nk = key length in 4-byte words (4/6/8 -> AES-128/192/256)
    Nr = rounds (10/12/14).  Total words = 4 * (Nr + 1).
    """
    nk = len(key_bytes) // 4
    nr = {4: 10, 6: 12, 8: 14}[nk]
    w = [list(key_bytes[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]                   # RotWord
            t = [AES_SBOX[b] for b in t]        # SubWord
            t[0] ^= AES_RCON[i // nk - 1]       # XOR round constant
        elif nk > 6 and i % nk == 4:
            t = [AES_SBOX[b] for b in t]        # extra SubWord for AES-256
        w.append([w[i - nk][j] ^ t[j] for j in range(4)])
    return w, nr


def aes_round_keys(key_bytes, verbose=True):
    """Print every round key - this is the 'key expansion' step."""
    w, nr = aes_key_expansion(key_bytes)
    keys = [b"".join(bytes(x) for x in w[4 * r:4 * r + 4])
            for r in range(nr + 1)]
    if verbose:
        print("key %d bits -> Nk=%d words, Nr=%d rounds, %d round keys"
              % (len(key_bytes) * 8, len(key_bytes) // 4, nr, len(keys)))
        for r, rk in enumerate(keys):
            tag = ("initial round (AddRoundKey)" if r == 0 else
                   "FINAL round (no MixColumns)" if r == nr else
                   "main round %d" % r)
            print("   RoundKey[%2d] = %s   <- %s"
                  % (r, rk.hex().upper(), tag))
    return keys, nr


def aes_show_steps(message, key, bits=192):
    """Full answer to 'show all the steps': key schedule + round list + run."""
    k = make_key(key, bits // 8)
    print("\n--- STEP 1: KEY EXPANSION ---")
    keys, nr = aes_round_keys(k)
    print("\n--- STEP 2: ROUND STRUCTURE ---")
    print("   round  0 : AddRoundKey")
    for r in range(1, nr):
        print("   round %2d : SubBytes -> ShiftRows -> MixColumns -> AddRoundKey" % r)
    print("   round %2d : SubBytes -> ShiftRows -> AddRoundKey  (no MixColumns)"
          % nr)
    print("\n--- STEP 3: ACTUAL ENCRYPTION ---")
    ct, _ = sym_encrypt(message, k, "AES-%d" % bits, "ECB")
    show("plaintext", message)
    show("ciphertext", ct.hex().upper())
    show("decrypted", sym_decrypt(ct, k, "AES-%d" % bits, "ECB").decode())
    return ct
# <<<<< END BLOCK: AESSTEPS <<<<<



# >>>>> BLOCK: RSA >>>>>
# ================ RSA: textbook + 2048-bit + hybrid  (Lab 3) ================
# needs: CORE  (hybrid also needs SYM)
from Crypto.PublicKey import RSA as _RSA
from Crypto.Cipher import PKCS1_OAEP


def rsa_keygen_textbook(p=61, q=53, e=17, bits=None):
    """Small-number RSA that shows the maths. bits=16 -> fresh primes."""
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
    """RSA-OAEP. Short data only (<190 bytes at 2048 bits)."""
    return PKCS1_OAEP.new(public_key).encrypt(read_input(data))


def rsa_decrypt(ciphertext, private_key):
    return PKCS1_OAEP.new(private_key).decrypt(ciphertext)


def rsa_hybrid_encrypt(data, public_key):
    """Any size: AES does the data, RSA protects the session key."""
    session = get_random_bytes(32)
    ct, nonce, tag = aes_gcm_encrypt(read_input(data), session)
    return rsa_encrypt(session, public_key), nonce, tag, ct


def rsa_hybrid_decrypt(enc_key, nonce, tag, ciphertext, private_key):
    session = rsa_decrypt(enc_key, private_key)
    return aes_gcm_decrypt(ciphertext, session, nonce, tag)
# <<<<< END BLOCK: RSA <<<<<


# >>>>> BLOCK: PERF >>>>>
# ===== ASYMMETRIC PERFORMANCE COMPARISON  (Lab 3 Q4/Q5, additional Q5) ======
#  "Measure and compare key generation time, encryption/decryption speed and
#   computational overhead."   needs: CORE + RSA  (ECC / ELGAMAL optional)
# ===========================================================================
def compare_asymmetric(sizes=(1024, 10240), rsa_bits=2048, curve="secp256r1"):
    """Time key generation, encryption and decryption for every asymmetric
    scheme that is present in this file. All of them use HYBRID encryption
    (the asymmetric part protects a random AES key) because none of them can
    encrypt kilobytes directly."""
    rows = []

    t0 = time.perf_counter()
    rsa_priv, rsa_pub = rsa_generate(rsa_bits)
    t_rsa_kg = time.perf_counter() - t0
    rows.append(("RSA-%d" % rsa_bits, t_rsa_kg))

    has_ecc = "ecc_keygen" in globals()
    if has_ecc:
        t0 = time.perf_counter()
        ecc_priv, ecc_pub = ecc_keygen(curve)
        rows.append(("ECC %s" % curve, time.perf_counter() - t0))

    print("\n--- key generation ---")
    for name, t in rows:
        print("   %-18s %9.2f ms" % (name, t * 1000))
    if has_ecc and rows[0][1] > 0:
        print("   -> ECC is about %.0fx faster to generate"
              % (rows[0][1] / max(rows[-1][1], 1e-9)))

    print("\n--- encryption / decryption (hybrid) ---")
    print("   %-10s %-18s %11s %11s %10s"
          % ("size", "scheme", "encrypt ms", "decrypt ms", "overhead"))
    out = []
    for n in sizes:
        data = os.urandom(n)
        label = "%d B" % n if n < 1024 else "%d KB" % (n // 1024)

        t0 = time.perf_counter()
        blob = rsa_hybrid_encrypt(data, rsa_pub)
        te = time.perf_counter() - t0
        t0 = time.perf_counter()
        back = rsa_hybrid_decrypt(*blob, rsa_priv)
        td = time.perf_counter() - t0
        assert back == data
        oh = len(blob[0]) + len(blob[1]) + len(blob[2])
        print("   %-10s %-18s %11.3f %11.3f %8d B"
              % (label, "RSA-%d" % rsa_bits, te * 1000, td * 1000, oh))
        out.append((label, "RSA", te, td, oh))

        if has_ecc:
            t0 = time.perf_counter()
            eph, nonce, ct = ecc_encrypt(data, ecc_pub)
            te = time.perf_counter() - t0
            t0 = time.perf_counter()
            back = ecc_decrypt(eph, nonce, ct, ecc_priv)
            td = time.perf_counter() - t0
            assert back == data
            # ephemeral public key serialised = what actually goes on the wire
            oh = len(eph.export_key(format="DER")) + len(nonce)
            print("   %-10s %-18s %11.3f %11.3f %8d B"
                  % (label, "ECC (ECIES)", te * 1000, td * 1000, oh))
            out.append((label, "ECC", te, td, oh))

    print("""
FINDINGS
  * RSA key generation is 50-100x slower - it must search for two large
    random primes; ECC just picks a random scalar.
  * RSA encryption is cheap (e = 65537 is only 17 bits) but RSA DECRYPTION
    is expensive (full-length private exponent). ECC costs one scalar
    multiplication on each side.
  * Overhead per message: RSA-2048 adds a 256-byte wrapped key, ECC P-256
    adds a ~91-byte ephemeral public key.
  * Equivalent security: RSA-2048 ~ ECC-256 ~ 112-bit symmetric.
  * Bulk speed is identical because AES does the actual work in both.""")
    return out
# <<<<< END BLOCK: PERF <<<<<



# >>>>> BLOCK: ELGAMAL >>>>>
# ==================== ELGAMAL ENCRYPTION  (Lab 3 Q3) ========================
# needs: CORE
def elgamal_keygen(p=467, g=2, x=None, bits=None):
    if bits:
        p, g = gen_prime(bits), 2
    x = x if x is not None else random.randint(2, p - 2)
    return (p, g, pow(g, x, p)), x


def elgamal_encrypt(message, public, k=None):
    p, g, h = public
    out = []
    for b in read_input(message):
        kk = k if k is not None else random.randint(2, p - 2)
        out.append((pow(g, kk, p), (b * pow(h, kk, p)) % p))
    return out


def elgamal_decrypt(pairs, private, public):
    p = public[0]
    return bytes((c2 * modinv(pow(c1, private, p), p)) % p
                 for c1, c2 in pairs)
# <<<<< END BLOCK: ELGAMAL <<<<<


# >>>>> BLOCK: RABIN >>>>>
# ======================= RABIN CRYPTOSYSTEM  (Lab 4) ========================
# needs: CORE
def rabin_keygen(bits=32):
    """p = q = 3 (mod 4). bits = total modulus size."""
    half = max(8, bits // 2)
    f = lambda v: v % 4 == 3
    p = gen_prime(half, cond=f)
    q = gen_prime(half, cond=f)
    while q == p:
        q = gen_prime(half, cond=f)
    return p * q, (p, q)


def rabin_encrypt(message, n):
    """Each byte duplicated (m*256+m) as redundancy -> unique decryption."""
    if n <= 65535:
        raise ValueError("use rabin_keygen(bits=32) or larger")
    return [pow(b * 256 + b, 2, n) for b in read_input(message)]


def rabin_roots(c, p, q):
    """The four square roots of c mod n."""
    n = p * q
    mp, mq = pow(c, (p + 1) // 4, p), pow(c, (q + 1) // 4, q)
    _, yp, yq = egcd(p, q)
    r1 = (yp * p * mq + yq * q * mp) % n
    r3 = (yp * p * mq - yq * q * mp) % n
    return [r1, n - r1, r3, n - r3]


def rabin_decrypt(cipher_list, private):
    p, q = private
    out = bytearray()
    for c in cipher_list:
        for r in rabin_roots(c, p, q):
            if r < 65536 and (r >> 8) == (r & 0xFF):
                out.append(r & 0xFF)
                break
        else:
            raise ValueError("no valid root - wrong key?")
    return bytes(out)
# <<<<< END BLOCK: RABIN <<<<<


# >>>>> BLOCK: DH >>>>>
# ==================== DIFFIE-HELLMAN KEY EXCHANGE  (Lab 3/6) ================
# needs: CORE
DH_P = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
           "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
           "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
           "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
           "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8"
           "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D"
           "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", 16)
DH_G = 2


def dh_keygen(p=23, g=5, private=None):
    """Use p=DH_P, g=DH_G for a real 2048-bit group."""
    priv = private if private is not None else random.randint(2, p - 2)
    return priv, pow(g, priv, p)


def dh_shared(their_public, my_private, p=23):
    return pow(their_public, my_private, p)


def dh_derive_key(shared_int, length=32, info=b"dh"):
    """Turn the shared integer into a usable symmetric key."""
    raw = shared_int.to_bytes((shared_int.bit_length() + 7) // 8 or 1, "big")
    return hashlib.sha256(info + raw).digest()[:length]


def dh_demo(p=23, g=5, label="Peer"):
    a, A = dh_keygen(p, g)
    b, B = dh_keygen(p, g)
    sa, sb = dh_shared(B, a, p), dh_shared(A, b, p)
    print("%s A: private=%s public=%s" % (label, a, A))
    print("%s B: private=%s public=%s" % (label, b, B))
    show("shared (A)", sa)
    show("shared (B)", sb)
    show("match", sa == sb)
    return sa == sb
# <<<<< END BLOCK: DH <<<<<


# >>>>> BLOCK: ECC >>>>>
# ============= ELLIPTIC CURVE: ECDH + AES-GCM hybrid  (Lab 3 Q2) ===========
# needs: CORE
# pycryptodome only - the "cryptography" package is deliberately NOT used,
# because it is a second native dependency and a machine that blocks unsigned
# binaries blocks it too.
from Crypto.Cipher import AES as _ECCAES
from Crypto.Hash import SHA256 as _ECCSHA
from Crypto.Protocol.KDF import HKDF
from Crypto.PublicKey import ECC

_ECC_CURVES = {"secp256r1": "P-256", "secp384r1": "P-384",
               "secp521r1": "P-521", "p256": "P-256", "p384": "P-384"}


def ecc_keygen(curve="secp256r1"):
    priv = ECC.generate(curve=_ECC_CURVES.get(curve, curve))
    return priv, priv.public_key()


def _ecc_shared(private_key, public_key, info):
    """ECDH: multiply the other side's point by your own scalar, then HKDF
    the x coordinate down to an AES key. Never use the raw point as a key."""
    point = public_key.pointQ * private_key.d
    raw = point.x.to_bytes(point.size_in_bytes(), "big")
    return HKDF(raw, 32, b"", _ECCSHA, context=info)


def ecc_encrypt(data, recipient_public, info=b"ECC"):
    """ECIES: ephemeral ECDH -> HKDF -> AES-GCM.
    Returns (ephemeral_public, nonce, ciphertext) with the GCM tag appended
    to the ciphertext."""
    eph = ECC.generate(curve=recipient_public.curve)
    key = _ecc_shared(eph, recipient_public, info)
    cipher = _ECCAES.new(key, _ECCAES.MODE_GCM, nonce=os.urandom(12))
    body, tag = cipher.encrypt_and_digest(read_input(data))
    return eph.public_key(), cipher.nonce, body + tag


def ecc_decrypt(ephemeral_public, nonce, ciphertext, my_private, info=b"ECC"):
    key = _ecc_shared(my_private, ephemeral_public, info)
    cipher = _ECCAES.new(key, _ECCAES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext[:-16], ciphertext[-16:])
# <<<<< END BLOCK: ECC <<<<<


# >>>>> BLOCK: HASH >>>>>
# ========================= HASHING  (Lab 5) =================================
# needs: CORE
def custom_hash(data):
    """Lab 5 Q1: start 5381, h=h*33+ord(c), XOR-shift mixing, 32-bit mask."""
    seq = data if isinstance(data, (bytes, bytearray)) else str(data).encode()
    h = 5381
    for b in seq:
        h = h * 33 + b
        h ^= (h >> 16)
    return h & 0xFFFFFFFF


def hash_data(data, algo="sha256"):
    """algo: custom | md5 | sha1 | sha224 | sha256 | sha384 | sha512"""
    data = read_input(data)
    if algo == "custom":
        return format(custom_hash(data), "08x")
    return hashlib.new(algo, data).hexdigest()


def hash_file(path, algo="sha256", chunk=65536):
    """Memory-safe hashing of large files."""
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
    """Keyed hash: integrity AND authenticity from a shared secret."""
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
    """Lab 5 Q3: timing + collision detection over random strings."""
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
    """Lab 5 Q3 collision detection, made visible.

    A collision means two DIFFERENT inputs give the SAME digest. With a full
    256-bit digest that never happens here, so we keep only the first n bits.
    Expect the first collision after roughly 2**(n/2) inputs - the birthday
    bound.
    """
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
            chars = b // 4                      # 4 bits per hex character
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
# <<<<< END BLOCK: HASH <<<<<


# >>>>> BLOCK: SIGN >>>>>
# ================== DIGITAL SIGNATURES  (Lab 6) =============================
# needs: CORE + HASH ; RSA block for RSA keys ; ECC block for ECDSA keys
from Crypto.Signature import pkcs1_15, pss, DSS
from Crypto.Hash import SHA256 as _CSHA256, SHA512 as _CSHA512
from Crypto.Hash import MD5 as _CMD5, SHA1 as _CSHA1

_PYCRYPTO_HASH = {"sha256": _CSHA256, "sha512": _CSHA512,
                  "md5": _CMD5, "sha1": _CSHA1}


def rsa_sign(data, private_key, scheme="pkcs1v15", algo="sha256"):
    """Hash then sign. scheme: pkcs1v15 | pss"""
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
    return DSS.new(private_key, "fips-186-3").sign(
        _CSHA256.new(read_input(data)))


def ecdsa_verify(data, signature, public_key):
    try:
        DSS.new(public_key, "fips-186-3").verify(
            _CSHA256.new(read_input(data)), signature)
        return True
    except Exception:
        return False


def elgamal_sign(data, public, x):
    """r = g^k mod p ; s = (H - x*r) * k^-1 mod (p-1).  Returns (r, s)."""
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
    """Signatures that are a pair of big numbers (ElGamal, Schnorr) print as
    enormous decimal strings. Show them in hex like every other answer."""
    if isinstance(signature, (tuple, list)):
        return "r=%s s=%s" % (hexs(signature[0]), hexs(signature[1]))
    if isinstance(signature, (bytes, bytearray)):
        return hexs(signature)
    return str(signature)


def elgamal_verify(data, signature, public):
    """Check  y^r * r^s  ==  g^H  (mod p)."""
    p, g, y = public
    r, s = signature
    if not 0 < r < p:
        return False
    h = int(hashlib.sha256(read_input(data)).hexdigest(), 16) % (p - 1)
    return (pow(y, r, p) * pow(r, s, p)) % p == pow(g, h, p)


SCHNORR_P, SCHNORR_Q, SCHNORR_G = 467, 233, 4      # q | p-1, g has order q


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
    """CIA triad in one call: encrypt + hash + sign."""
    ct, iv = sym_encrypt(read_input(data), sym_key, algo, mode)
    return {"ciphertext": ct.hex(), "iv": iv.hex() if iv else None,
            "hash": hashlib.sha256(ct).hexdigest(),
            "signature": rsa_sign(ct, sender_priv).hex(),
            "algo": algo, "mode": mode, "time": timestamp()}


def secure_receive(packet, sender_pub, sym_key):
    """Verify signature + hash, then decrypt. Returns (plaintext, report)."""
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


# --- raw ("textbook") RSA signature - the format the Lab 6 manual uses ------
#  The online tool in the manual does NOT hash: it treats the text as one big
#  number m and outputs s = m^d mod n.  Verifying is s^e mod n, which prints
#  the name back. Shown here so you can reproduce Tables 2 and 4 exactly.
def format_hex_sig(data):
    """bytes -> '0xc8 0x93 0xa9 ...' (the manual's display format)."""
    return " ".join("0x%02x" % b for b in data)


def parse_hex_sig(text):
    """'0xc8 0x93 ...' -> bytes."""
    return bytes(int(t, 16) for t in text.split())


def rsa_sign_raw(text, n, d):
    """s = m^d mod n, with the text read directly as an integer."""
    m = int.from_bytes(text.encode() if isinstance(text, str) else text, "big")
    return pow(m, d, n)


def rsa_verify_raw(signature_int, n, e):
    """Apply the PUBLIC exponent: returns (integer, bytes). The bytes are the
    original text - which is exactly what the website's Verify button shows."""
    v = pow(signature_int, e, n)
    return v, v.to_bytes((v.bit_length() + 7) // 8 or 1, "big")


def rsa_raw_demo(text="Alice", bits=1024):
    """Sign a name with raw RSA and read it back, manual-style."""
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
# <<<<< END BLOCK: SIGN <<<<<


# >>>>> BLOCK: KMS >>>>>
# ============== KEY MANAGEMENT SYSTEM  (Lab 4 Q1 / Q2) ======================
# needs: CORE + SYM (+ RSA / RABIN / ELGAMAL / DH for the scheme you pick)
class KeyManager:
    """km = KeyManager("RABIN", 32)
       km.generate("Hospital_A"); km.distribute("Hospital_A")
       km.revoke("Clinic_C"); km.renew("Hospital_A"); km.audit()"""

    def __init__(self, scheme="RSA", bits=2048, storage_key=None,
                 logfile="key_management.log", lifetime_days=365):
        self.scheme, self.bits = scheme.upper(), bits
        self.lifetime = timedelta(days=lifetime_days)
        self.store = {}
        self.master = storage_key or get_random_bytes(32)
        self.logfile = logfile

    def _log(self, action, entity, extra=""):
        with open(self.logfile, "a") as f:
            f.write("%s - %s - %s %s\n" % (timestamp(), action, entity, extra))

    def _seal(self, text):
        """Private keys are stored ENCRYPTED (secure storage requirement)."""
        ct, nonce, tag = aes_gcm_encrypt(text.encode(), self.master)
        return {"ct": ct.hex(), "nonce": nonce.hex(), "tag": tag.hex()}

    def _unseal(self, blob):
        return aes_gcm_decrypt(bytes.fromhex(blob["ct"]), self.master,
                               bytes.fromhex(blob["nonce"]),
                               bytes.fromhex(blob["tag"])).decode()

    def _make_pair(self):
        if self.scheme == "RSA":
            k = _RSA.generate(self.bits)
            return (k.publickey().export_key().decode(),
                    k.export_key().decode())
        if self.scheme == "RABIN":
            n, (p, q) = rabin_keygen(self.bits)
            return str(n), "%d:%d" % (p, q)
        if self.scheme == "ELGAMAL":
            pub, x = elgamal_keygen(bits=max(16, self.bits // 64))
            return json.dumps(pub), str(x)
        if self.scheme == "DH":
            priv, pub = dh_keygen(DH_P, DH_G)
            return str(pub), str(priv)
        raise ValueError("scheme: RSA / RABIN / ELGAMAL / DH")

    def generate(self, entity, verbose=True):
        pub, priv = self._make_pair()
        now = datetime.now()
        self.store[entity] = {
            "public": pub, "private": self._seal(priv),
            "scheme": self.scheme, "bits": self.bits,
            "created": now.strftime("%Y-%m-%d %H:%M:%S"),
            "expires": (now + self.lifetime).strftime("%Y-%m-%d %H:%M:%S"),
            "status": "ACTIVE"}
        self._log("KEY GENERATED", entity, "(%s/%d)" % (self.scheme, self.bits))
        if verbose:
            print("[KMS] generated %s key for %s (expires %s)"
                  % (self.scheme, entity, self.store[entity]["expires"]))
        return pub

    def distribute(self, entity, include_private=False):
        rec = self.store.get(entity)
        if not rec:
            print("[KMS] unknown entity:", entity)
            return None
        if rec["status"] == "REVOKED":
            print("[KMS] key for %s is REVOKED - refused" % entity)
            return None
        self._log("KEY DISTRIBUTED", entity)
        out = {"public": rec["public"]}
        if include_private:
            out["private"] = self._unseal(rec["private"])
        print("[KMS] distributed key material for", entity)
        return out

    def revoke(self, entity, reason="unspecified"):
        if entity not in self.store:
            return False
        self.store[entity]["status"] = "REVOKED"
        self._log("KEY REVOKED", entity, "reason=" + reason)
        print("[KMS] revoked", entity, "(%s)" % reason)
        return True

    def renew(self, entity):
        if entity not in self.store:
            return None
        self.generate(entity, verbose=False)
        self._log("KEY RENEWED", entity)
        print("[KMS] renewed key for", entity)
        return self.store[entity]["public"]

    def check_expiry(self):
        now, done = datetime.now(), []
        for e, r in list(self.store.items()):
            if datetime.strptime(r["expires"], "%Y-%m-%d %H:%M:%S") <= now:
                self.renew(e)
                done.append(e)
        return done

    def status(self):
        print("\n%-16s %-9s %-10s %-20s"
              % ("ENTITY", "SCHEME", "STATUS", "EXPIRES"))
        print("-" * 58)
        for e, r in self.store.items():
            print("%-16s %-9s %-10s %-20s"
                  % (e, r["scheme"], r["status"], r["expires"]))

    def audit(self, lines=20):
        print("\n--- audit log (%s) ---" % self.logfile)
        try:
            with open(self.logfile) as f:
                for ln in f.readlines()[-lines:]:
                    print("  ", ln.rstrip())
        except FileNotFoundError:
            print("   (empty)")
# <<<<< END BLOCK: KMS <<<<<


# >>>>> BLOCK: ACCESS >>>>>
# ============= ACCESS CONTROL MODELS  (Lab 4) ===============================
# needs: CORE
class RBAC:
    """Role-Based Access Control."""

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
    """Attribute-Based: policy(u, o, e) -> bool."""
    return bool(policy(user_attrs, object_attrs, env_attrs))


LEVELS = {"PUBLIC": 0, "CONFIDENTIAL": 1, "SECRET": 2, "TOPSECRET": 3}


def bell_lapadula(subject_level, object_level, action):
    """No read-up, no write-down."""
    s, o = LEVELS[subject_level.upper()], LEVELS[object_level.upper()]
    if action == "read":
        return s >= o            # simple security property
    if action == "write":
        return s <= o            # * property
    return False


def mac_allowed(clearance, classification, policy_ok=True):
    return LEVELS[clearance.upper()] >= LEVELS[classification.upper()] \
        and policy_ok


class DAC:
    """Discretionary Access Control - access matrix."""

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
    """Limited-time access (DRM style)."""

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
# <<<<< END BLOCK: ACCESS <<<<<


# >>>>> BLOCK: SOCKET >>>>>
# ============ CLIENT-SERVER over sockets  (Lab 5 Q2 / Lab 6 Q3) =============
# needs: CORE + HASH (+ RSA/SIGN for signature demo, DH+SYM for channel)
def send_msg(sock, payload):
    """Length-prefixed send - avoids partial reads."""
    if isinstance(payload, str):
        payload = payload.encode()
    sock.sendall(len(payload).to_bytes(4, "big") + payload)


def recv_msg(sock):
    raw = _recv_exact(sock, 4)
    return None if raw is None else _recv_exact(sock,
                                                int.from_bytes(raw, "big"))


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def run_server_client(server_fn, client_fn, host="localhost"):
    """Runs the server in a thread on a free port; client in main thread."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def _serve():
        try:
            conn, _ = srv.accept()
            try:
                server_fn(conn)
            finally:
                conn.close()
        finally:
            srv.close()

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    cli = socket.socket()
    cli.connect((host, port))
    try:
        result = client_fn(cli)
    finally:
        cli.close()
    t.join(timeout=5)
    return result


def socket_integrity_demo(message="Information Security Lab",
                          algo="sha256", tamper=False):
    """Server hashes what it receives; client compares with its own hash."""
    original = read_input(message)
    sent = bytearray(original)
    if tamper:
        sent[0] ^= 0xFF

    def server(conn):
        send_msg(conn, hash_data(recv_msg(conn), algo))

    def client(conn):
        send_msg(conn, bytes(sent))
        return recv_msg(conn).decode()

    server_hash = run_server_client(server, client)
    local = hash_data(original, algo)
    ok = server_hash == local
    print("\n--- socket integrity (%s, tamper=%s) ---" % (algo, tamper))
    show("local hash", local)
    show("server hash", server_hash)
    print("RESULT:", "Data Integrity Verified" if ok
          else "Data Corrupted or Tampered")
    return ok


def socket_multipart_demo(message="This message is sent in several parts",
                          parts=4, algo="sha256"):
    """Client sends in chunks; server reassembles then hashes."""
    data = read_input(message)
    size = max(1, len(data) // parts + 1)
    chunks = [data[i:i + size] for i in range(0, len(data), size)]

    def server(conn):
        buf = b""
        while True:
            p = recv_msg(conn)
            if p is None or p == b"<END>":
                break
            buf += p
        send_msg(conn, hash_data(buf, algo))

    def client(conn):
        for c in chunks:
            send_msg(conn, c)
        send_msg(conn, b"<END>")
        return recv_msg(conn).decode()

    sh = run_server_client(server, client)
    local = hash_data(data, algo)
    print("\n--- multi-part reassembly (%d chunks) ---" % len(chunks))
    show("local hash", local)
    show("server hash", sh)
    print("RESULT:", "Reassembled correctly" if sh == local else "MISMATCH")
    return sh == local


def socket_signature_demo(message="Sign this document", tamper=False):
    """Server signs with RSA private key; client verifies with public key."""
    priv, pub = rsa_generate(2048)

    def server(conn):
        send_msg(conn, rsa_sign(recv_msg(conn), priv))

    def client(conn):
        send_msg(conn, read_input(message))
        return recv_msg(conn)

    sig = run_server_client(server, client)
    checked = (b"Tampered " + read_input(message)) if tamper \
        else read_input(message)
    ok = rsa_verify(checked, sig, pub)
    print("\n--- socket RSA signature (tamper=%s) ---" % tamper)
    show("signature", preview(sig, 48))
    print("RESULT:", "Signature Verified" if ok else "Invalid Signature")
    return ok


def socket_secure_channel_demo(message="Confidential payload"):
    """Diffie-Hellman key agreement then AES-GCM encrypted transfer."""
    def server(conn):
        b_priv, b_pub = dh_keygen(DH_P, DH_G)
        a_pub = int(recv_msg(conn).decode())
        send_msg(conn, str(b_pub))
        key = dh_derive_key(dh_shared(a_pub, b_priv, DH_P))
        nonce, tag, ct = recv_msg(conn), recv_msg(conn), recv_msg(conn)
        send_msg(conn, b"RECEIVED:" + aes_gcm_decrypt(ct, key, nonce, tag))

    def client(conn):
        a_priv, a_pub = dh_keygen(DH_P, DH_G)
        send_msg(conn, str(a_pub))
        key = dh_derive_key(dh_shared(int(recv_msg(conn).decode()),
                                      a_priv, DH_P))
        ct, nonce, tag = aes_gcm_encrypt(read_input(message), key)
        send_msg(conn, nonce)
        send_msg(conn, tag)
        send_msg(conn, ct)
        return recv_msg(conn)

    echo = run_server_client(server, client)
    ok = echo == b"RECEIVED:" + read_input(message)
    print("\n--- DH + AES-GCM secure channel ---")
    show("server echo", echo.decode(errors="replace"))
    print("RESULT:", "Secure channel OK" if ok else "FAILED")
    return ok


SERVER_TEMPLATE = '''"""Standalone server - hashes received data and returns it."""
import socket, hashlib
HOST, PORT = "localhost", 5000
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((HOST, PORT)); s.listen(1)
print("Server listening on", HOST, PORT)
conn, addr = s.accept()
print("Connected by", addr)
data = conn.recv(4096)
digest = hashlib.sha256(data).hexdigest()
print("Received :", data.decode(errors="replace"))
print("Hash sent:", digest)
conn.send(digest.encode())
conn.close(); s.close()
'''

CLIENT_TEMPLATE = '''"""Standalone client - verifies the hash returned by the server."""
import socket, hashlib
HOST, PORT = "localhost", 5000
s = socket.socket(); s.connect((HOST, PORT))
data = input("Enter data: ").encode()
s.send(data)
server_hash = s.recv(4096).decode()
local_hash = hashlib.sha256(data).hexdigest()
print("Local  hash:", local_hash)
print("Server hash:", server_hash)
print("Data Integrity Verified" if local_hash == server_hash
      else "Data Corrupted or Tampered")
s.close()
'''


def write_socket_templates(folder="."):
    """Create separate server.py + client.py when the examiner wants 2 files."""
    a = write_output(os.path.join(folder, "server.py"), SERVER_TEMPLATE)
    b = write_output(os.path.join(folder, "client.py"), CLIENT_TEMPLATE)
    print("wrote", a, "and", b, "- run server first, then client")
    return a, b
# <<<<< END BLOCK: SOCKET <<<<<


# >>>>> BLOCK: ATTACK >>>>>
# ============ CRYPTANALYSIS  (Lab 1 Q5/Q6, Lab 4 additional Q2) =============
# needs: CORE + CLASSIC_SUB (for the affine/additive helpers)
def brute_force_additive(cipher, show_all=True, hint_days=None):
    """All 26 shift keys. hint_days=(10,16) narrows to a birthday range."""
    t = clean_text(cipher)
    keys = range(26) if not hint_days else range(hint_days[0], hint_days[1] + 1)
    out = []
    for k in keys:
        g = additive_decrypt(t, k)
        out.append((k, g))
        if show_all:
            print("key %2d : %s" % (k, g))
    return out


def affine_known_plaintext(p1, c1, p2, c2):
    """Recover (a,b) from two letter pairs: affine_known_plaintext('a','G','b','L')"""
    i = lambda ch: ord(ch.upper()) - 65
    p1, c1, p2, c2 = i(p1), i(c1), i(p2), i(c2)
    inv = modinv((p2 - p1) % 26, 26)
    if inv is None:
        raise ValueError("cannot solve from these pairs")
    a = ((c2 - c1) * inv) % 26
    return a, (c1 - a * p1) % 26


def affine_brute_force(cipher, crib=None, limit=20):
    """Try every valid (a,b); crib filters results containing that word."""
    t, hits = clean_text(cipher), []
    for a in range(1, 26):
        if gcd(a, 26) != 1:
            continue
        for b in range(26):
            g = affine_decrypt(t, a, b)
            if crib is None or crib.upper() in g:
                hits.append((a, b, g))
    for a, b, g in hits[:limit]:
        print("a=%2d b=%2d : %s" % (a, b, g))
    return hits


def shift_from_pair(plain, cipher):
    """Shift key from one known pair: shift_from_pair('yes','CIW') -> 4"""
    return (ord(cipher[0].upper()) - ord(plain[0].upper())) % 26


def frequency_analysis(cipher, top=6):
    t = clean_text(cipher)
    ranked = sorted({c: t.count(c) for c in set(t)}.items(),
                    key=lambda kv: -kv[1])[:top]
    print("most frequent:", ", ".join("%s=%d" % kv for kv in ranked))
    print("(English order: E T A O I N S H R D L U)")
    return ranked


def permutation_key_size(plain, cipher, verbose=True):
    """Transposition only rearranges letters, so each block is a permutation."""
    p, c = clean_text(plain), clean_text(cipher)
    n = min(len(p), len(c))
    p, c = p[:n], c[:n]
    best = None
    for size in range(2, min(n, 12) + 1):
        if n % size:
            continue
        blocks = n // size
        matched = sum(sorted(p[i:i + size]) == sorted(c[i:i + size])
                      for i in range(0, n, size))
        score = matched / blocks
        if best is None or score > best[1]:
            perm = [p[:size].index(ch) + 1 for ch in c[:size]] \
                if score == 1.0 else None
            best = (size, score, perm)
    if verbose and best:
        print("best block size : %d (%.0f%% of blocks are permutations)"
              % (best[0], best[1] * 100))
        if best[2]:
            print("permutation key :", best[2])
        elif best[1] < 1:
            print("note: not exact - check the given data for typos")
    return best[0] if best else None


def factor_rsa_small(n, verbose=True):
    """Weak-prime attack: factor n by trial division."""
    t0 = time.perf_counter()
    if n % 2 == 0:
        return 2, n // 2
    i = 3
    while i * i <= n:
        if n % i == 0:
            if verbose:
                print("factored %d in %.4f s -> p=%d q=%d"
                      % (n, time.perf_counter() - t0, i, n // i))
            return i, n // i
        i += 2
    return None


def fermat_factor(n, max_steps=1000000, verbose=True):
    """Weak-prime attack for p and q CHOSEN TOO CLOSE TOGETHER.

    n = a*a - b*b = (a-b)(a+b).  Start at a = ceil(sqrt(n)) and step up until
    a*a - n is a perfect square.  Breaks a 2048-bit key in milliseconds when
    the primes are adjacent - trial division would never finish.
    """
    t0 = time.perf_counter()
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for step in range(max_steps):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            p, q = a - b, a + b
            if verbose:
                print("Fermat: %d steps, %.4f s -> |p-q| = %d"
                      % (step + 1, time.perf_counter() - t0, abs(p - q)))
            return p, q
        a += 1
    if verbose:
        print("Fermat failed - the primes are far enough apart")
    return None


def shared_prime_attack(n1, n2, verbose=True):
    """If two moduli share a prime, gcd(n1, n2) finds it instantly and BOTH
    private keys fall. This is a real bug found across the internet in 2012."""
    g = math.gcd(n1, n2)
    if g == 1:
        if verbose:
            print("no shared prime")
        return None
    if verbose:
        print("shared prime found by gcd -> both keys compromised")
    return g, n1 // g, n2 // g


def factor_rsa(n, verbose=True):
    """Try the cheap attacks in order: trial division, then Fermat."""
    if n.bit_length() <= 64:
        f = factor_rsa_small(n, verbose)
        if f:
            return f
    return fermat_factor(n, verbose=verbose)


def recover_rsa_private(n, e, verbose=True):
    """Full private-key recovery once n is factorable + mitigation notes."""
    f = factor_rsa(n, verbose)
    if not f:
        print("could not factor - primes are large enough")
        return None
    p, q = f
    phi = (p - 1) * (q - 1)
    d = modinv(e, phi)
    if verbose:
        print("phi(n) =", phi, " recovered d =", d)
        print("MITIGATION: 2048-bit random primes, large |p-q|, e=65537,")
        print("            use a vetted library, never hand-rolled key gen.")
    return {"p": p, "q": q, "phi": phi, "d": d}
# <<<<< END BLOCK: ATTACK <<<<<


# >>>>> BLOCK: DISPATCH >>>>>
# ===========================================================================
#  UNIVERSAL DISPATCHER - makes EVERY cipher interchangeable.
#  Because of this block, switching the scenario system from DES to the
#  Hill cipher (or Vigenere, or Playfair, or AES-256-CBC) is ONE line.
#  needs: CORE + whichever cipher blocks you actually name in CONFIG
# ===========================================================================
CLASSICAL_CIPHERS = {"ADDITIVE", "MULTIPLICATIVE", "AFFINE", "VIGENERE",
                     "AUTOKEY", "PLAYFAIR", "HILL", "TRANSPOSITION"}
MODERN_CIPHERS = {"DES", "3DES", "AES-128", "AES-192", "AES-256"}

# what each cipher expects as its key
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
    """Accept the key in whatever form the question gives it."""
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
    return key                       # keywords / byte keys pass through


def encrypt_any(data, cfg):
    """data -> (ciphertext_bytes, iv).  Works for classical AND modern."""
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
    """(ciphertext_bytes, iv) -> plaintext bytes."""
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
    """Classical ciphertext is readable letters; modern is shown as hex."""
    if cfg["cipher"].upper() in CLASSICAL_CIPHERS:
        return safe_text(ciphertext)
    return ciphertext.hex()


def cipher_note(cfg):
    """Warn about the one real difference between the two families."""
    if cfg["cipher"].upper() in CLASSICAL_CIPHERS:
        return ("classical cipher: A-Z only, so spaces, digits and "
                "punctuation are dropped by design")
    return "block cipher: any byte content is preserved exactly"


# --- signature dispatch -----------------------------------------------------

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
    """Turn a key pair into JSON-storable form."""
    s = scheme.upper()
    if s == "RSA":
        return {"scheme": s, "private": priv.export_key().decode(),
                "public": pub.export_key().decode()}
    if s == "ECDSA":
        return {"scheme": s,
                "private": priv.export_key(format="PEM"),
                "public": pub.export_key(format="PEM")}
    return {"scheme": s, "private": priv, "public": list(pub)}


def sig_deserialize(rec):
    s = rec["scheme"].upper()
    if s == "RSA":
        return _RSA.import_key(rec["private"]), _RSA.import_key(rec["public"])
    if s == "ECDSA":
        return ECC.import_key(rec["private"]), ECC.import_key(rec["public"])
    return rec["private"], tuple(rec["public"])
# <<<<< END BLOCK: DISPATCH <<<<<


# >>>>> BLOCK: TEMPLATE >>>>>
# ===========================================================================
#  SCENARIO ANSWER TEMPLATE - menu-driven role-based secure system.
#  EduSecure / HealthCare / Banking / Legal / HR / e-Governance ...
#
#  EDIT ONLY THESE TWO DICTIONARIES:
#      CONFIG  - which algorithms                ROLES - who may do what
#
#  Examples:
#      CONFIG["cipher"]="AES-256"; CONFIG["mode"]="CBC"
#      CONFIG["cipher"]="HILL";      CONFIG["key"]=[[3,3],[2,7]]
#      CONFIG["cipher"]="VIGENERE";  CONFIG["key"]="dollars"
#      CONFIG["signature"]="ECDSA";  CONFIG["hash"]="sha512"
#  needs: CORE + DISPATCH + the cipher/hash/signature blocks you name
# ===========================================================================
# --- defaults: an emitted CONFIG/ROLES at the TOP of a built file wins -------
if "CONFIG" not in globals():
    CONFIG = {
        "system_name": "EduSecure",
        "cipher":      "DES",     # any classical or modern name (see KEY_HELP)
        "mode":        "ECB",     # ECB CBC CFB OFB CTR (modern ciphers only)
        "key":         "A1B2C3D4",
        "signature":   "RSA",     # RSA | ECDSA | ELGAMAL | SCHNORR
        "rsa_bits":    2048,
        "hash":        "sha256",  # md5 sha1 sha256 sha512 custom
        "sign_target": "cipher",  # sign the ciphertext, or "plain"
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
    """Role-based secure document system driven entirely by CONFIG."""

    def __init__(self, config=None, roles=None):
        self.cfg = dict(CONFIG)
        self.cfg.update(config or {})
        self.roles = roles or ROLES
        os.makedirs(self.cfg["key_dir"], exist_ok=True)
        self.records = self._load(self.cfg["db_file"], [])
        self.keystore = self._load(
            os.path.join(self.cfg["key_dir"], "keystore.json"), {})

    # ---- persistence -------------------------------------------------------
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

    # ---- keys --------------------------------------------------------------
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

    # ---- access control ----------------------------------------------------
    def allowed(self, role, permission):
        return permission in self.roles.get(role, {}).get("permissions", [])

    def require(self, role, permission):
        if not self.allowed(role, permission):
            raise PermissionError("role '%s' may not '%s'" % (role, permission))
        return True

    # ---- core operations ---------------------------------------------------
    def upload(self, owner, data, filename="record.txt", verbose=True):
        """Encrypt -> hash -> sign -> store with timestamp."""
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
        """Decrypt + verify signature + recompute hash; store the result."""
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
        """Corrupt one byte - proves the integrity checks actually work."""
        rec = next((r for r in self.records if r["id"] == rec_id), None)
        if not rec:
            return None
        ct = bytearray(bytes.fromhex(rec["ciphertext"]))
        if self.cfg["cipher"].upper() in CLASSICAL_CIPHERS:
            ct[0] = ord("A") + (ct[0] - ord("A") + 1) % 26   # keep it A-Z
        else:
            ct[0] ^= 0xFF
        rec["ciphertext"] = bytes(ct).hex()
        self._save()
        self._log("TAMPER SIMULATED - record #%d" % rec_id)
        if verbose:
            print("\n[!] record #%d deliberately corrupted" % rec_id)
        return rec

    # ---- menu actions ------------------------------------------------------
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
        """HoD view: hashes + signature status only, never the content."""
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

    # ---- menus -------------------------------------------------------------
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
                self.require(role, perm)          # access control enforced
                getattr(self, ACTIONS[perm][1])(user)
            except PermissionError as ex:
                print("ACCESS DENIED:", ex)
            except Exception as ex:
                print("error:", ex)

    # ---- no-typing demonstration ------------------------------------------
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
    """Read a whole file and CLOSE it.

    `open(p).read()` leaves the handle to the garbage collector. On Windows
    that handle is what makes the next delete fail with 'Access is denied',
    so every read in this file goes through here."""
    with open(path, encoding=encoding) as f:
        return f.read()


def count_lines(path):
    """Line count, with the file properly closed."""
    with open(path, encoding="utf-8") as f:
        return sum(1 for _ in f)


def tidy(*paths):
    """Delete scratch files and folders without ever raising.

    Windows keeps a handle open for a moment after writing (OneDrive,
    antivirus), so a plain os.remove can fail with 'Access is denied'. None
    of this is worth crashing over."""
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
    """Clear records / keys / logs so a demo starts fresh.

    Deliberately forgiving: on Windows, OneDrive and antivirus scanners hold
    a handle open for a moment after a file is written, and os.rmdir then
    fails with 'Access is denied'. Nothing here is important enough to crash
    the program over, so every removal is best-effort."""
    import shutil
    cfg = cfg or CONFIG
    for p in (cfg["db_file"], cfg["log_file"]):
        try:
            if os.path.exists(p):
                os.remove(p)
        except OSError:
            pass
    shutil.rmtree(cfg["key_dir"], ignore_errors=True)
# <<<<< END BLOCK: TEMPLATE <<<<<


# ###########################################################################
# #                                                                         #
# #   PLAYSHEET TOOLING BELOW - DO NOT PASTE THIS INTO YOUR ANSWER FILE.    #
# #   It only exists to check the environment, build answer files and       #
# #   prove every block above actually works.                               #
# #                                                                         #
# ###########################################################################

BLOCK_ORDER = ["CORE", "CLASSIC_SUB", "CLASSIC_POLY", "CLASSIC_PLAYFAIR",
               "CLASSIC_HILL", "CLASSIC_TRANS", "SYM", "AESSTEPS", "RSA",
               "PERF", "ELGAMAL", "RABIN", "DH", "ECC", "HASH", "SIGN",
               "KMS", "ACCESS", "SOCKET", "ATTACK", "DISPATCH", "TEMPLATE"]

ALL_CLASSIC = ["CLASSIC_SUB", "CLASSIC_POLY", "CLASSIC_PLAYFAIR",
               "CLASSIC_HILL", "CLASSIC_TRANS"]

PRESETS = {
    "exam":      ["CORE", "SYM", "RSA", "HASH", "SIGN", "DISPATCH",
                  "ACCESS", "TEMPLATE"],
    "classical": ["CORE"] + ALL_CLASSIC + ["SYM", "RSA", "HASH", "SIGN",
                                           "DISPATCH", "ACCESS", "TEMPLATE"],
    "network":   ["CORE", "SYM", "RSA", "DH", "HASH", "SIGN", "SOCKET",
                  "DISPATCH"],
    "keymgmt":   ["CORE", "SYM", "RSA", "RABIN", "ELGAMAL", "DH", "HASH",
                  "KMS", "ACCESS"],
    "lab1":      ["CORE"] + ALL_CLASSIC + ["ATTACK"],
    "lab2":      ["CORE", "SYM", "AESSTEPS"],
    "lab3":      ["CORE", "SYM", "RSA", "PERF", "ELGAMAL", "DH", "ECC"],
    "lab4":      ["CORE", "SYM", "RSA", "RABIN", "ELGAMAL", "DH", "HASH",
                  "KMS", "ACCESS", "ATTACK"],
    "lab5":      ["CORE", "HASH", "SOCKET"],
    "lab6":      ["CORE", "SYM", "RSA", "ECC", "ELGAMAL", "DH", "HASH",
                  "SIGN", "SOCKET"],
    "all":       BLOCK_ORDER,
}


def _source_path():
    return os.path.abspath(__file__)


def extract_blocks():
    """Read this file and return {block_name: source_text}."""
    blocks, current, buf = {}, None, []
    with open(_source_path(), encoding="utf-8") as f:
        for line in f:
            if line.startswith("# >>>>> BLOCK:"):
                current = line.split("BLOCK:")[1].split(">>>>>")[0].strip()
                buf = []
            elif line.startswith("# <<<<< END BLOCK:") and current:
                blocks[current] = "".join(buf)
                current = None
            elif current is not None:
                buf.append(line)
    return blocks


def list_blocks():
    blocks = extract_blocks()
    print("\nAvailable blocks (%d):" % len(blocks))
    for name in BLOCK_ORDER:
        if name in blocks:
            lines = blocks[name].count("\n")
            print("   %-18s %4d lines" % (name, lines))
    print("\nPresets:")
    for k, v in PRESETS.items():
        print("   %-10s %s" % (k, " ".join(v)))


def build_answer(selection="exam", out="answer.py", quiet=False):
    """Assemble chosen blocks into a standalone runnable file."""
    blocks = extract_blocks()
    if isinstance(selection, str):
        names = PRESETS.get(selection.lower()) or \
            [s.strip().upper() for s in selection.split(",")]
    else:
        names = list(selection)

    if "CORE" not in names:
        names = ["CORE"] + names
    names = [n for n in BLOCK_ORDER if n in names]     # canonical order

    missing = [n for n in names if n not in blocks]
    if missing:
        print("unknown block(s):", ", ".join(missing))
        return None

    parts = ['"""',
             'Information Security Lab - answer file',
             'Generated from playsheet blocks: ' + ", ".join(names),
             'Generated on ' + timestamp(),
             '"""',
             '']

    # A built file that contains the scenario system gets the same editable
    # CONFIG/ROLES header the wizard writes, so --reconfigure works on it too.
    if "TEMPLATE" in names:
        parts += [
            CONFIG_START,
            '# Change anything here and re-run - nothing else needs editing.',
            'CONFIG = {',
            '    "system_name": "SecureSystem",',
            '    "cipher":      "DES",',
            '    "mode":        "ECB",',
            '    "key":         "A1B2C3D4",',
            '    "signature":   "RSA",',
            '    "rsa_bits":    2048,',
            '    "hash":        "sha256",',
            '    "sign_target": "cipher",',
            '    "db_file":     "records.json",',
            '    "key_dir":     "keys",',
            '    "log_file":    "audit.log",',
            '}',
            '',
            'ROLES = {',
        ] + ['    "%s": {"label": "%s", "permissions": %s},'
             % (rid, label, repr(perms)) for rid, label, perms in DEFAULT_ROLES
             ] + ['}', CONFIG_END, '']
    for n in names:
        parts.append(blocks[n].rstrip())
        parts.append("")

    if "TEMPLATE" in names:
        parts += [
            "",
            "# ============================ RUN =========================",
            "# python <file>        the menu",
            "# python <file> demo   whole flow, no typing",
            "# python <file> reset  clear records / keys / log",
            "if __name__ == '__main__':",
            "    import sys",
            "    _arg = sys.argv[1] if len(sys.argv) > 1 else ''",
            "    if _arg == 'reset':",
            "        reset_demo_files()",
            "    elif _arg == 'demo':",
            "        reset_demo_files()",
            "        SecureSystem().demo()",
            "    else:",
            "        SecureSystem().menu()",
            "",
        ]
    write_output(out, "\n".join(parts))
    write_clean_twin(out, quiet=quiet)
    if not quiet:
        n_lines = len("\n".join(parts).split("\n"))
        print("built %s  (%d blocks, %d lines)" % (out, len(names), n_lines))
        print("blocks:", " + ".join(names))
        print("run it with:  python %s" % out)
    return out



# ===========================================================================
#  INTERACTIVE BUILDER (wizard)
#     python playsheet.py --wizard                 build a new answer file
#     python playsheet.py --reconfigure answer.py  change an existing one
# ===========================================================================

CONFIG_START = "# ===== EDIT THIS SECTION - CONFIG START ====="
SETTINGS_START = "# ===== SETTINGS - change these to match the question ====="
SETTINGS_END = "# ===== END SETTINGS ====="
CONFIG_END = "# ===== CONFIG END ====="

# cipher -> (default key, default mode, block needed, key hint)
CIPHER_TABLE = [
    ("DES", "A1B2C3D4", "ECB", "SYM", "8 characters"),
    ("3DES", "1234567890ABCDEF9012344321ABCDEF1234567890ABCDEF", "ECB", "SYM",
     "48 hex chars"),
    ("AES-128", "0123456789ABCDEF0123456789ABCDEF", "ECB", "SYM",
     "32 hex chars"),
    ("AES-192", "FEDCBA9876543210FEDCBA98", "ECB", "SYM", "24 chars"),
    ("AES-256",
     "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
     "CBC", "SYM", "64 hex chars"),
    ("ADDITIVE", "20", "-", "CLASSIC_SUB", "integer shift"),
    ("MULTIPLICATIVE", "15", "-", "CLASSIC_SUB", "integer coprime with 26"),
    ("AFFINE", "15,20", "-", "CLASSIC_SUB", "a,b"),
    ("VIGENERE", "dollars", "-", "CLASSIC_POLY", "keyword"),
    ("AUTOKEY", "7", "-", "CLASSIC_POLY", "integer seed or keyword"),
    ("PLAYFAIR", "GUIDANCE", "-", "CLASSIC_PLAYFAIR", "keyword"),
    ("HILL", "3,3;2,7", "-", "CLASSIC_HILL", "rows separated by ;"),
    ("TRANSPOSITION", "3142", "-", "CLASSIC_TRANS", "digits or a word"),
]

SIG_TABLE = [
    ("RSA", ["RSA", "SIGN"]),
    ("ECDSA", ["ECC", "SIGN"]),
    ("ELGAMAL", ["ELGAMAL", "SIGN"]),
    ("SCHNORR", ["SIGN"]),
    ("NONE", []),
]

HASH_TABLE = ["sha256", "sha512", "sha1", "md5", "custom"]

ROLE_PRESETS = {
    "1": ("Education (Student / Faculty / HoD)", [
        ("student", "Student", ["upload", "view_own"]),
        ("faculty", "Faculty", ["decrypt_verify", "view_all", "tamper_test"]),
        ("hod", "HoD", ["view_hashes", "audit"])]),
    "2": ("Healthcare (Patient / Doctor / Admin)", [
        ("patient", "Patient", ["upload", "view_own"]),
        ("doctor", "Doctor", ["decrypt_verify", "view_all", "tamper_test"]),
        ("admin", "Admin", ["view_hashes", "audit"])]),
    "3": ("Banking (Customer / Officer / Auditor)", [
        ("customer", "Customer", ["upload", "view_own"]),
        ("officer", "Bank Officer", ["decrypt_verify", "view_all",
                                     "tamper_test"]),
        ("auditor", "Auditor", ["view_hashes", "audit"])]),
    "4": ("Corporate (Employee / Manager / Director)", [
        ("employee", "Employee", ["upload", "view_own"]),
        ("manager", "Manager", ["decrypt_verify", "view_all", "tamper_test"]),
        ("director", "Director", ["view_hashes", "audit"])]),
    "5": ("Legal (Client / Lawyer / Judge)", [
        ("client", "Client", ["upload", "view_own"]),
        ("lawyer", "Lawyer", ["decrypt_verify", "view_all", "tamper_test"]),
        ("judge", "Judge", ["view_hashes", "audit"])]),
}

EXTRA_TABLE = [
    ("SOCKET", "client-server over sockets (integrity + signature demos)"),
    ("KMS", "key management: generate / distribute / revoke / renew / log"),
    ("ACCESS", "extra access models: Bell-LaPadula, ABAC, DAC, time-based"),
    ("ATTACK", "cryptanalysis: brute force, known-plaintext, RSA factoring"),
    ("DH", "Diffie-Hellman key exchange"),
    ("RABIN", "Rabin cryptosystem"),
    ("ELGAMAL", "ElGamal encryption"),
    ("ECC", "ECC / ECDH hybrid encryption"),
]

ALL_PERMISSIONS = ["upload", "view_own", "decrypt_verify", "view_all",
                   "view_hashes", "tamper_test", "audit"]


def _ask(prompt, default=""):
    d = " [%s]" % default if default != "" else ""
    try:
        v = input("%s%s: " % (prompt, d)).strip()
    except EOFError:
        v = ""
    return v or default


def _ask_choice(prompt, options, default="1"):
    """options: list of display strings. Returns the chosen index (0-based)."""
    for i, o in enumerate(options, 1):
        print("   %2d - %s" % (i, o))
    while True:
        v = _ask(prompt, default)
        if v.isdigit() and 1 <= int(v) <= len(options):
            return int(v) - 1
        print("   pick a number between 1 and %d" % len(options))


def _fmt_key(cipher, key):
    """Emit the key in the most readable literal form."""
    c = cipher.upper()
    if c in ("ADDITIVE", "MULTIPLICATIVE"):
        try:
            return repr(int(key))
        except ValueError:
            return repr(key)
    if c == "HILL":
        try:
            return repr([[int(v) for v in row.split(",")]
                         for row in str(key).split(";")])
        except ValueError:
            return repr(key)
    return repr(key)


def wizard(out_default="answer.py", full=False):
    """Interactive builder: asks a few questions, writes a ready answer file."""
    print("\n" + "=" * 64)
    print("  INTERACTIVE ANSWER BUILDER")
    print("  Answer the questions (press Enter to accept the default).")
    print("=" * 64)

    name = _ask("\n1. System name from the question", "EduSecure")

    print("\n2. Which cipher protects the data?")
    labels = ["%-15s (%s)" % (c[0], c[4]) for c in CIPHER_TABLE]
    ci = _ask_choice("   choice", labels, "1")
    cipher, defkey, defmode, cblock, hint = CIPHER_TABLE[ci]

    key = _ask("   key for %s (%s)" % (cipher, hint), defkey)

    mode = "-"
    if cblock == "SYM":
        print("\n3. Mode of operation")
        modes = ["ECB (simplest)", "CBC (needs IV - recommended)",
                 "CFB", "OFB", "CTR"]
        mode = ["ECB", "CBC", "CFB", "OFB", "CTR"][
            _ask_choice("   choice", modes,
                        str(["ECB", "CBC", "CFB", "OFB", "CTR"]
                            .index(defmode) + 1))]

    print("\n4. Digital signature scheme")
    si = _ask_choice("   choice", [s[0] for s in SIG_TABLE], "1")
    signature, sblocks = SIG_TABLE[si]

    print("\n5. Hash algorithm")
    hi = _ask_choice("   choice", HASH_TABLE, "1")
    hashalgo = HASH_TABLE[hi]

    print("\n6. Sign the ciphertext or the plaintext?")
    st = ["cipher", "plain"][_ask_choice(
        "   choice",
        ["ciphertext (read-only roles can verify without decrypting)",
         "plaintext"], "1")]

    print("\n7. User roles")
    keys = sorted(ROLE_PRESETS)
    pi = _ask_choice("   choice",
                     [ROLE_PRESETS[k][0] for k in keys] + ["Custom roles"],
                     "1")
    if pi < len(keys):
        roles = ROLE_PRESETS[keys[pi]][1]
    else:
        roles = []
        print("   permissions available:", ", ".join(ALL_PERMISSIONS))
        n = int(_ask("   how many roles", "3") or 3)
        for i in range(n):
            label = _ask("   role %d display name" % (i + 1), "Role%d" % (i + 1))
            perms = _ask("   role %d permissions (comma separated)" % (i + 1),
                         "upload,view_own")
            roles.append((label.lower().replace(" ", "_"), label,
                          [p.strip() for p in perms.split(",") if p.strip()]))

    print("\n8. Anything extra the question asks for?")
    print("   (comma separated numbers, or Enter for none)")
    for i, (blk, desc) in enumerate(EXTRA_TABLE, 1):
        print("   %2d - %-8s %s" % (i, blk, desc))
    raw = _ask("   choice", "")
    extras = []
    for tok in raw.replace(" ", "").split(","):
        if tok.isdigit() and 1 <= int(tok) <= len(EXTRA_TABLE):
            extras.append(EXTRA_TABLE[int(tok) - 1][0])

    out = _ask("\n9. Output filename", out_default)

    blocks = ["CORE", "SYM", "HASH", "DISPATCH", "TEMPLATE",
              cblock] + sblocks + extras
    if "KMS" in blocks and "RSA" not in blocks:
        blocks.append("RSA")
    if "SOCKET" in blocks:
        blocks += ["RSA", "SIGN", "DH"]
    if "ATTACK" in blocks and cblock.startswith("CLASSIC"):
        blocks.append("CLASSIC_SUB")
    elif "ATTACK" in blocks:
        blocks.append("CLASSIC_SUB")

    cfg = {"system_name": name, "cipher": cipher, "mode": mode, "key": key,
           "signature": signature if signature != "NONE" else "RSA",
           "hash": hashalgo, "sign_target": st}

    # LEAN is the default: only the cipher, signature and hash you picked.
    # --full pastes every block instead (bigger, but has all the extras).
    lean = not (full or extras)
    if extras:
        print("\n   (extras requested -> writing the FULL version so the"
              " extra blocks come with it)")
    path = emit_lean(cfg, roles, out) if lean \
        else emit_answer(blocks, cfg, roles, out)

    print("\n" + "=" * 64)
    print("  BUILT: %s" % path)
    print("=" * 64)
    print("  cipher    : %s%s" % (cipher, "" if mode == "-" else " / " + mode))
    print("  key       : %s" % key)
    print("  signature : %s" % cfg["signature"])
    print("  hash      : %s" % hashalgo)
    print("  roles     : %s" % ", ".join(r[1] for r in roles))
    if lean:
        print("  style     : LEAN - only the cipher, hash and signature above")
    else:
        print("  blocks    : %s" % " + ".join(
            [b for b in BLOCK_ORDER if b in set(blocks)]))
    print("  size      : %d lines" % count_lines(path))
    print("  files     : %s  (commented, for you)" % path)
    print("              %s  (no comments, to show)" % clean_name(path))
    print("\n  run it       :  python %s" % path)
    print("  demo, no typing: python %s demo" % path)
    print("  reconfigure  :  python playsheet.py --reconfigure %s" % path)
    print("  or just edit the SETTINGS block at the top of the file.")
    return path


# ===========================================================================
#  LEAN EMITTER - writes a SMALL answer file in plain, flat, exam style.
#
#  Written to match how the answers are actually handed in: straight-line
#  functions, module-level settings, plain print() with aligned labels, no
#  helper layer and no class wrapping everything.
# ===========================================================================

LEAN_HEAD = '''# %(name)s - Information Security Lab
# %(cipher)s%(modetxt)s encryption + %(hash)s hashing + %(sig)s digital signature
# Roles: %(rolelist)s
#
#   python %(outfile)s         menu
#   python %(outfile)s demo    full run, no typing
#   python %(outfile)s reset   clear saved records and keys

%(imports)s
import hashlib
import json
import sys
import os
from datetime import datetime

# A Windows console cannot print every byte. Without this the tamper test
# would stop the program instead of showing the result.
try:
    sys.stdout.reconfigure(errors="replace")
except Exception:
    pass


# ===== SETTINGS - change these to match the question =====
system_name = "%(name)s"
%(keyline)s
roles = {
%(roles)s
}
# ===== END SETTINGS =====

records = []
user_keys = {}

record_file = "records.json"
key_file = "keys.json"
log_file = "audit.log"


def timestamp():
    return datetime.now().strftime("%%Y-%%m-%%d %%H:%%M:%%S")
'''

# --------------------------------------------------------------------------
#  ENCRYPTION - one block per cipher family
# --------------------------------------------------------------------------

LEAN_MODERN = '''

# ---------- Encryption and Decryption (%(cipher)s / %(mode)s) ----------
def encrypt_data(message):
    %(enc_body)s


def decrypt_data(ciphertext, iv):
    %(dec_body)s


def show_cipher(ciphertext):
    return ciphertext.hex().upper()
'''

MODERN_BODIES = {
"ECB": ('''cipher = %(mod)s.new(key, %(mod)s.MODE_ECB)
    ciphertext = cipher.encrypt(pad(message.encode(), %(mod)s.block_size))
    return ciphertext, b""''',
        '''cipher = %(mod)s.new(key, %(mod)s.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), %(mod)s.block_size).decode()'''),

"CBC": ('''iv = get_random_bytes(%(mod)s.block_size)
    cipher = %(mod)s.new(key, %(mod)s.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(message.encode(), %(mod)s.block_size))
    return ciphertext, iv''',
        '''cipher = %(mod)s.new(key, %(mod)s.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), %(mod)s.block_size).decode()'''),

"CFB": ('''iv = get_random_bytes(%(mod)s.block_size)
    cipher = %(mod)s.new(key, %(mod)s.MODE_CFB, iv)
    return cipher.encrypt(message.encode()), iv''',
        '''cipher = %(mod)s.new(key, %(mod)s.MODE_CFB, iv)
    return cipher.decrypt(ciphertext).decode()'''),

"OFB": ('''iv = get_random_bytes(%(mod)s.block_size)
    cipher = %(mod)s.new(key, %(mod)s.MODE_OFB, iv)
    return cipher.encrypt(message.encode()), iv''',
        '''cipher = %(mod)s.new(key, %(mod)s.MODE_OFB, iv)
    return cipher.decrypt(ciphertext).decode()'''),

"CTR": ('''nonce = get_random_bytes(%(mod)s.block_size // 2)
    cipher = %(mod)s.new(key, %(mod)s.MODE_CTR, nonce=nonce)
    return cipher.encrypt(message.encode()), nonce''',
        '''cipher = %(mod)s.new(key, %(mod)s.MODE_CTR, nonce=iv)
    return cipher.decrypt(ciphertext).decode()'''),
}

LEAN_CLASSIC_HEAD = '''

# ---------- Encryption and Decryption (%(cipher)s cipher) ----------
# A classical cipher works on A-Z only, so spaces, digits and punctuation
# are removed before encrypting.
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def clean_text(text):
    return "".join(ch for ch in str(text).upper() if ch.isalpha())


def mod_inverse(a, m=26):
    a = a %% m
    for x in range(1, m):
        if a * x %% m == 1:
            return x
    raise ValueError("no inverse for %%d mod %%d" %% (a, m))
'''

LEAN_CLASSIC_TAIL = '''

def encrypt_data(message):
    return encrypt_text(message).encode(), b""


def decrypt_data(ciphertext, iv):
    return decrypt_text(ciphertext.decode())


def show_cipher(ciphertext):
    return "%s   (hex %s)" % (ciphertext.decode(), ciphertext.hex().upper())
'''

LEAN_CIPHERS = {
"ADDITIVE": '''

def encrypt_text(message):
    return "".join(chr((ord(ch) - 65 + key) %% 26 + 65)
                   for ch in clean_text(message))


def decrypt_text(ciphertext):
    return "".join(chr((ord(ch) - 65 - key) %% 26 + 65)
                   for ch in clean_text(ciphertext))
''',

"MULTIPLICATIVE": '''

def encrypt_text(message):
    return "".join(chr((ord(ch) - 65) * key %% 26 + 65)
                   for ch in clean_text(message))


def decrypt_text(ciphertext):
    key_inverse = mod_inverse(key)
    return "".join(chr((ord(ch) - 65) * key_inverse %% 26 + 65)
                   for ch in clean_text(ciphertext))
''',

"AFFINE": '''

def encrypt_text(message):
    a, b = key
    return "".join(chr(((ord(ch) - 65) * a + b) %% 26 + 65)
                   for ch in clean_text(message))


def decrypt_text(ciphertext):
    a, b = key
    a_inverse = mod_inverse(a)
    return "".join(chr(a_inverse * (ord(ch) - 65 - b) %% 26 + 65)
                   for ch in clean_text(ciphertext))
''',

"VIGENERE": '''

def encrypt_text(message):
    text = clean_text(message)
    word = clean_text(key)
    return "".join(chr((ord(text[i]) - 65 + ord(word[i %% len(word)]) - 65)
                       %% 26 + 65) for i in range(len(text)))


def decrypt_text(ciphertext):
    text = clean_text(ciphertext)
    word = clean_text(key)
    return "".join(chr((ord(text[i]) - 65 - (ord(word[i %% len(word)]) - 65))
                       %% 26 + 65) for i in range(len(text)))
''',

"AUTOKEY": '''
# The keystream is the key followed by the plaintext itself, so it never
# repeats.

def key_start():
    if str(key).strip().lstrip("-").isdigit():
        return [int(key) %% 26]
    return [ord(ch) - 65 for ch in clean_text(key)]


def encrypt_text(message):
    plain = [ord(ch) - 65 for ch in clean_text(message)]
    stream = key_start() + plain
    return "".join(chr((plain[i] + stream[i]) %% 26 + 65)
                   for i in range(len(plain)))


def decrypt_text(ciphertext):
    cipher = [ord(ch) - 65 for ch in clean_text(ciphertext)]
    stream = key_start()
    plain = []
    for i in range(len(cipher)):
        value = (cipher[i] - stream[i]) %% 26
        plain.append(value)
        stream.append(value)
    return "".join(chr(value + 65) for value in plain)
''',

"PLAYFAIR": '''
# 5x5 key square, two letters at a time. I and J share one cell.

def build_matrix():
    letters = []
    for ch in clean_text(key).replace("J", "I") + "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if ch not in letters:
            letters.append(ch)
    return [letters[i * 5:i * 5 + 5] for i in range(5)]


def find_position(matrix, ch):
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == ch:
                return row, col


def make_pairs(message):
    text = clean_text(message).replace("J", "I")
    pairs = []
    i = 0
    while i < len(text):
        a = text[i]
        b = text[i + 1] if i + 1 < len(text) else "X"
        if a == b:
            pairs.append(a + "X")
            i += 1
        else:
            pairs.append(a + b)
            i += 2
    return pairs


def run_playfair(text, step):
    matrix = build_matrix()
    if step == 1:
        pairs = make_pairs(text)
    else:
        clean = clean_text(text).replace("J", "I")
        pairs = [clean[i:i + 2] for i in range(0, len(clean), 2)]
    result = ""
    for a, b in pairs:
        row1, col1 = find_position(matrix, a)
        row2, col2 = find_position(matrix, b)
        if row1 == row2:
            result += matrix[row1][(col1 + step) %% 5]
            result += matrix[row2][(col2 + step) %% 5]
        elif col1 == col2:
            result += matrix[(row1 + step) %% 5][col1]
            result += matrix[(row2 + step) %% 5][col2]
        else:
            result += matrix[row1][col2] + matrix[row2][col1]
    return result


def encrypt_text(message):
    return run_playfair(message, 1)


def decrypt_text(ciphertext):
    return run_playfair(ciphertext, -1)
''',

"HILL": '''
# Matrix multiplication mod 26. Decryption needs the inverse of the key
# matrix, which exists only when gcd(determinant, 26) == 1.

def determinant(matrix):
    size = len(matrix)
    if size == 1:
        return matrix[0][0] %% 26
    if size == 2:
        return (matrix[0][0] * matrix[1][1]
                - matrix[0][1] * matrix[1][0]) %% 26
    total = 0
    for col in range(size):
        minor = [row[:col] + row[col + 1:] for row in matrix[1:]]
        total += ((-1) ** col) * matrix[0][col] * determinant(minor)
    return total %% 26


def inverse_matrix(matrix):
    size = len(matrix)
    det_inverse = mod_inverse(determinant(matrix))
    adjugate = [[0] * size for _ in range(size)]
    for i in range(size):
        for j in range(size):
            minor = [row[:j] + row[j + 1:]
                     for r, row in enumerate(matrix) if r != i]
            adjugate[j][i] = ((-1) ** (i + j) * determinant(minor)) %% 26
    return [[adjugate[i][j] * det_inverse %% 26 for j in range(size)]
            for i in range(size)]


def apply_matrix(message, matrix):
    size = len(matrix)
    numbers = [ord(ch) - 65 for ch in clean_text(message)]
    while len(numbers) %% size:
        numbers.append(23)
    result = []
    for i in range(0, len(numbers), size):
        block = numbers[i:i + size]
        for row in matrix:
            result.append(sum(row[j] * block[j]
                              for j in range(size)) %% 26)
    return "".join(chr(value + 65) for value in result)


def encrypt_text(message):
    return apply_matrix(message, key)


def decrypt_text(ciphertext):
    return apply_matrix(ciphertext, inverse_matrix(key))
''',

"TRANSPOSITION": '''
# Columnar transposition: write the text in rows under the key, then read
# the columns off in the key's order. Letters are moved, never changed.

def column_order():
    text = str(key)
    if text.isdigit():
        return [int(ch) - 1 for ch in text]
    return [i for _, i in sorted((ch, i)
                                 for i, ch in enumerate(text.upper()))]


def encrypt_text(message):
    order = column_order()
    size = len(order)
    text = clean_text(message)
    text += "X" * ((-len(text)) %% size)
    rows = [text[i:i + size] for i in range(0, len(text), size)]
    return "".join("".join(row[col] for row in rows) for col in order)


def decrypt_text(ciphertext):
    order = column_order()
    size = len(order)
    text = clean_text(ciphertext)
    row_count = len(text) // size
    columns = {}
    position = 0
    for col in order:
        columns[col] = text[position:position + row_count]
        position += row_count
    return "".join("".join(columns[col][row] for col in range(size))
                   for row in range(row_count))
''',
}

# --------------------------------------------------------------------------
#  HASHING
# --------------------------------------------------------------------------

LEAN_HASH = '''

# ---------- Hashing (%(hash)s) ----------
def hash_data(data):
    return hashlib.%(hash)s(data).hexdigest()
'''

LEAN_HASH_CUSTOM = '''

# ---------- Hashing (custom 32-bit hash) ----------
# Start at 5381, multiply by 33 and add each character, then mask to 32 bits.
def hash_data(data):
    hash_value = 5381
    for byte in data:
        hash_value = ((hash_value * 33) + byte) & 0xFFFFFFFF
    return "%08x" % hash_value
'''

# --------------------------------------------------------------------------
#  DIGITAL SIGNATURE - one block per scheme
#  Each one defines: get_keys(user), sign_data(data, user),
#                    verify_signature(data, signature, user),
#                    save_keys(), load_keys()
# --------------------------------------------------------------------------

LEAN_SIGN = {
"RSA": '''

# ---------- Digital Signature (RSA) ----------
def get_keys(user):
    if user not in user_keys:
        user_keys[user] = RSA.generate(2048)
        print("Generated RSA key pair for", user)
        save_keys()
    key_pair = user_keys[user]
    return key_pair, key_pair.publickey()


def sign_data(data, user):
    private_key, public_key = get_keys(user)
    return pkcs1_15.new(private_key).sign(SHA256.new(data)).hex()


def verify_signature(data, signature, user):
    private_key, public_key = get_keys(user)
    try:
        pkcs1_15.new(public_key).verify(SHA256.new(data),
                                        bytes.fromhex(signature))
        return True
    except (ValueError, TypeError):
        return False


def save_keys():
    with open(key_file, "w") as f:
        json.dump({u: k.export_key().decode()
                   for u, k in user_keys.items()}, f)


def load_keys():
    if os.path.exists(key_file):
        with open(key_file) as f:
            for user, pem in json.load(f).items():
                user_keys[user] = RSA.import_key(pem)
''',

"ECDSA": '''

# ---------- Digital Signature (ECDSA on curve P-256) ----------
def get_keys(user):
    if user not in user_keys:
        user_keys[user] = ECC.generate(curve="P-256")
        print("Generated ECDSA key pair for", user)
        save_keys()
    key_pair = user_keys[user]
    return key_pair, key_pair.public_key()


def sign_data(data, user):
    private_key, public_key = get_keys(user)
    signer = DSS.new(private_key, "fips-186-3")
    return signer.sign(SHA256.new(data)).hex()


def verify_signature(data, signature, user):
    private_key, public_key = get_keys(user)
    try:
        verifier = DSS.new(public_key, "fips-186-3")
        verifier.verify(SHA256.new(data), bytes.fromhex(signature))
        return True
    except ValueError:
        return False


def save_keys():
    with open(key_file, "w") as f:
        json.dump({u: k.export_key(format="PEM")
                   for u, k in user_keys.items()}, f)


def load_keys():
    if os.path.exists(key_file):
        with open(key_file) as f:
            for user, pem in json.load(f).items():
                user_keys[user] = ECC.import_key(pem)
''',

"ELGAMAL": '''

# ---------- Digital Signature (ElGamal) ----------
# r = g^k mod p
# s = (H(m) - x*r) * k^-1 mod (p-1)        signature is (r, s)
# verify:  g^H(m)  ==  y^r * r^s  (mod p)
p = 91185207321183015155495153901876504940934195032199180397683690774723603094143
g = 2


def mod_inverse_big(a, m):
    return pow(a, -1, m)


def get_keys(user):
    if user not in user_keys:
        x = random.randrange(2, p - 2)
        user_keys[user] = (x, pow(g, x, p))
        print("Generated ElGamal key pair for", user)
        save_keys()
    return user_keys[user]


def message_hash(data):
    return int(hashlib.sha256(data).hexdigest(), 16) % (p - 1)


def sign_data(data, user):
    private_key, public_key = get_keys(user)
    h = message_hash(data)
    while True:
        k = random.randrange(2, p - 2)
        if math.gcd(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    s = (h - private_key * r) * mod_inverse_big(k, p - 1) % (p - 1)
    return "%x,%x" % (r, s)


def verify_signature(data, signature, user):
    private_key, public_key = get_keys(user)
    try:
        r, s = [int(part, 16) for part in signature.split(",")]
    except ValueError:
        return False
    if not 0 < r < p:
        return False
    left = pow(g, message_hash(data), p)
    right = pow(public_key, r, p) * pow(r, s, p) % p
    return left == right


def save_keys():
    with open(key_file, "w") as f:
        json.dump({u: [str(v) for v in pair]
                   for u, pair in user_keys.items()}, f)


def load_keys():
    if os.path.exists(key_file):
        with open(key_file) as f:
            for user, pair in json.load(f).items():
                user_keys[user] = (int(pair[0]), int(pair[1]))
''',

"SCHNORR": '''

# ---------- Digital Signature (Schnorr) ----------
# r = g^k mod p ;  e = H(r || m) mod q ;  s = (k + x*e) mod q
# verify: rebuild r from g^s * y^-e mod p and check the hash matches
p = 91185207321183015155495153901876504940934195032199180397683690774723603094143
q = 45592603660591507577747576950938252470467097516099590198841845387361801547071
g = 4


def get_keys(user):
    if user not in user_keys:
        x = random.randrange(1, q)
        user_keys[user] = (x, pow(g, x, p))
        print("Generated Schnorr key pair for", user)
        save_keys()
    return user_keys[user]


def challenge(data, r):
    return int(hashlib.sha256(str(r).encode() + data).hexdigest(), 16) % q


def sign_data(data, user):
    private_key, public_key = get_keys(user)
    k = random.randrange(1, q)
    r = pow(g, k, p)
    e = challenge(data, r)
    return "%x,%x" % (e, (k + private_key * e) % q)


def verify_signature(data, signature, user):
    private_key, public_key = get_keys(user)
    try:
        e, s = [int(part, 16) for part in signature.split(",")]
    except ValueError:
        return False
    r = pow(g, s, p) * pow(public_key, q - e % q, p) % p
    return challenge(data, r) == e


def save_keys():
    with open(key_file, "w") as f:
        json.dump({u: [str(v) for v in pair]
                   for u, pair in user_keys.items()}, f)


def load_keys():
    if os.path.exists(key_file):
        with open(key_file) as f:
            for user, pair in json.load(f).items():
                user_keys[user] = (int(pair[0]), int(pair[1]))
''',
}

# --------------------------------------------------------------------------
#  STORAGE, ACCESS CONTROL, THE OPERATIONS AND THE MENU
# --------------------------------------------------------------------------

LEAN_BODY = '''

# ---------- Saving and loading ----------
def save_records():
    with open(record_file, "w") as f:
        json.dump(records, f, indent=2)


def load_records():
    if os.path.exists(record_file):
        with open(record_file) as f:
            records.extend(json.load(f))


def find_record(record_id):
    for record in records:
        if record["id"] == record_id:
            return record
    return None


# ---------- Audit log ----------
def log_action(text):
    with open(log_file, "a") as f:
        f.write(timestamp() + " - " + text + "\\n")


def show_log():
    if not os.path.exists(log_file):
        print("The log is empty")
        return
    with open(log_file) as f:
        print(f.read().strip())


# ---------- Access Control ----------
def check_permission(role, action):
    if action not in roles.get(role, []):
        print("ACCESS DENIED:", role, "is not allowed to", action)
        return False
    return True


# ---------- Upload: encrypt, hash, then sign ----------
def upload_record(user, message):
    ciphertext, iv = encrypt_data(message)
    digest = hash_data(ciphertext)
    signature = sign_data(ciphertext, user)

    record = {
        "id": len(records) + 1,
        "owner": user,
        "ciphertext": ciphertext.hex(),
        "iv": iv.hex(),
        "hash": digest,
        "signature": signature,
        "time": timestamp()
    }

    records.append(record)
    save_records()
    log_action("UPLOAD by " + user + " - record " + str(record["id"]))

    print("\\n----- Record Uploaded -----")
    print("Owner      :", user)
    print("Ciphertext :", show_cipher(ciphertext))
    print("Hash       :", digest)
    print("Signature  :", signature)
    print("Timestamp  :", record["time"])
    return record


# ---------- Verify: check the hash, check the signature, then decrypt ----------
def verify_record(record_id):
    record = find_record(record_id)

    if record is None:
        print("No record with id", record_id)
        return

    ciphertext = bytes.fromhex(record["ciphertext"])

    recomputed = hash_data(ciphertext)
    integrity_ok = recomputed == record["hash"]

    signature_ok = verify_signature(ciphertext, record["signature"],
                                    record["owner"])

    try:
        message = decrypt_data(ciphertext, bytes.fromhex(record["iv"]))
    except Exception:
        message = "<cannot decrypt - the record was modified>"

    print("\\n----- Verification of Record", record_id, "-----")
    print("Owner      :", record["owner"])
    print("Uploaded   :", record["time"])
    print("Plaintext  :", message)
    print("Stored Hash:", record["hash"])
    print("Recomputed :", recomputed)
    print("Integrity  :", "OK" if integrity_ok else "FAILED - record modified")
    print("Signature  :", "VALID" if signature_ok else "INVALID")

    log_action("VERIFY record " + str(record_id)
               + " integrity=" + str(integrity_ok)
               + " signature=" + str(signature_ok))


# ---------- Tamper test: change one byte and verify again ----------
def tamper_record(record_id):
    record = find_record(record_id)

    if record is None:
        print("No record with id", record_id)
        return

    data = bytearray(bytes.fromhex(record["ciphertext"]))

    if 65 <= data[0] <= 90:
        data[0] = 65 + (data[0] - 65 + 1) % 26
    else:
        data[0] = data[0] ^ 0xFF

    record["ciphertext"] = bytes(data).hex()
    save_records()

    log_action("TAMPER simulated on record " + str(record_id))
    print("\\nRecord", record_id, "was deliberately corrupted")


# ---------- Views ----------
def show_my_records(user):
    mine = [r for r in records if r["owner"] == user]

    if not mine:
        print("No records for", user)
        return

    for record in mine:
        print("\\nRecord", record["id"], "uploaded", record["time"])
        print("Ciphertext :", record["ciphertext"].upper())
        print("Hash       :", record["hash"])


def show_all_records():
    if not records:
        print("No records stored")
        return

    print("\\n%-4s %-12s %-22s %s" % ("ID", "OWNER", "UPLOADED", "HASH"))
    for record in records:
        print("%-4d %-12s %-22s %s" % (record["id"], record["owner"],
                                       record["time"], record["hash"][:32]))


def show_hashes():
    if not records:
        print("No records stored")
        return

    for record in records:
        ciphertext = bytes.fromhex(record["ciphertext"])
        valid = verify_signature(ciphertext, record["signature"],
                                 record["owner"])
        print("\\nRecord", record["id"], "owner", record["owner"],
              "uploaded", record["time"])
        print("Hash      :", record["hash"])
        print("Signature :", "VALID" if valid else "INVALID")
'''

LEAN_MENU = '''

# ---------- Menu ----------
def do_action(role, user, action):
    if not check_permission(role, action):
        return

    if action == "upload":
        upload_record(user, input("Record text: "))
    elif action == "view_own":
        show_my_records(user)
    elif action == "view_all":
        show_all_records()
    elif action == "decrypt_verify":
        show_all_records()
        verify_record(int(input("Record id: ")))
    elif action == "tamper_test":
        show_all_records()
        record_id = int(input("Record id to corrupt: "))
        tamper_record(record_id)
        verify_record(record_id)
    elif action == "view_hashes":
        show_hashes()
    elif action == "audit":
        show_log()


def menu():
    print("=" * 55)
    print(" ", system_name)
    print("=" * 55)

    while True:
        print("\\nLogin as:")
        names = list(roles)
        for i, name in enumerate(names, 1):
            print(" ", i, "-", name)
        print("  0 - Exit")

        choice = input("Select role: ").strip()

        if choice == "0":
            return
        if not choice.isdigit() or not 1 <= int(choice) <= len(names):
            continue

        role = names[int(choice) - 1]
        user = input("Username: ").strip() or role

        while True:
            print("\\n[", role, "]")
            actions = roles[role]
            for i, action in enumerate(actions, 1):
                print(" ", i, "-", action)
            print("  0 - Logout")

            pick = input("Choice: ").strip()

            if pick == "0":
                break
            if not pick.isdigit() or not 1 <= int(pick) <= len(actions):
                continue

            try:
                do_action(role, user, actions[int(pick) - 1])
            except ValueError:
                print("Enter a number")


def reset():
    for path in (record_file, key_file, log_file):
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            pass
    records.clear()
    user_keys.clear()
    print("Cleared saved records and keys")
'''

LEAN_DEMO = '''

# ---------- Full run with no typing ----------
def demo():
    print("=" * 55)
    print(" ", system_name, "-", "%(cipher)s%(modetxt)s +",
          "%(hash)s +", "%(sig)s signature")
    print("=" * 55)

    student = "%(demo_user)s"
    record = upload_record(student, "Semester 5 marks: DBMS 9 CN 8 OS 10")

    verify_record(record["id"])

    print("\\n----- %(read_only)s sees hashes only -----")
    show_hashes()

    print("\\n----- Access control check -----")
    check_permission("%(read_only_id)s", "decrypt_verify")

    print("\\n----- Tamper test -----")
    tamper_record(record["id"])
    verify_record(record["id"])

    print("\\nThe hash no longer matches and the signature is invalid,")
    print("which is exactly what they are there to detect.")


load_records()
load_keys()

if __name__ == "__main__":
    argument = sys.argv[1] if len(sys.argv) > 1 else ""

    if argument == "reset":
        reset()
    elif argument == "demo":
        reset()
        demo()
    else:
        menu()
'''

# ---------------------------------------------------------------------------
#  CLEAN TWIN - the same program with the teaching comments taken out.
#  answer.py       keeps every comment, for you
#  answer_clean.py identical behaviour, no comments or docstrings - this is
#                  the one that looks like a finished submission.
# ---------------------------------------------------------------------------

def strip_comments(source):
    """Remove comments and docstrings without changing what the code does.

    Uses tokenize to find the real comments, so a '#' inside a string is
    left alone, and ast to find docstrings. Blank runs are collapsed."""
    import io
    import ast
    import tokenize

    lines = source.splitlines()
    drop = set()                       # whole lines to delete
    cut = {}                           # line -> column to truncate at

    # --- comments (tokenize knows a '#' in a string is not a comment) ------
    # Section banners like  # ---------- Hashing ----------  are kept: they
    # are structure, not explanation, and a wall of functions with no
    # headings is harder to read, not cleaner.
    try:
        for tok in tokenize.generate_tokens(io.StringIO(source).readline):
            if tok.type != tokenize.COMMENT:
                continue
            if tok.string.startswith(("# ----------", "# =====")):
                continue               # section banner / SETTINGS marker
            row, col = tok.start
            cut[row] = min(cut.get(row, col), col)
    except (tokenize.TokenError, IndentationError):
        pass                           # unparseable: fall through, keep source

    # --- docstrings (module, class and function) ---------------------------
    try:
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Module, ast.ClassDef,
                                     ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            body = getattr(node, "body", [])
            if len(body) <= 1:
                continue               # removing it would empty the block
            first = body[0]
            if (isinstance(first, ast.Expr)
                    and isinstance(getattr(first, "value", None), ast.Constant)
                    and isinstance(first.value.value, str)):
                for ln in range(first.lineno, first.end_lineno + 1):
                    drop.add(ln)
    except SyntaxError:
        return source

    out = []
    for i, line in enumerate(lines, 1):
        if i in drop:
            continue
        if i in cut:
            line = line[:cut[i]].rstrip()
            if not line:
                continue               # the line was only a comment
        out.append(line.rstrip())

    # collapse 2+ blank lines down to one, and drop leading blanks
    cleaned, blanks = [], 0
    for line in out:
        if line.strip():
            blanks = 0
            cleaned.append(line)
        else:
            blanks += 1
            if blanks == 1 and cleaned:
                cleaned.append("")
    while cleaned and not cleaned[-1].strip():
        cleaned.pop()
    return "\n".join(cleaned) + "\n"


def clean_name(path):
    """answer.py -> answer_clean.py"""
    base, ext = os.path.splitext(path)
    return base + "_clean" + (ext or ".py")


def write_clean_twin(path, cfg=None, quiet=False):
    """Write the comment-free twin of an answer file next to it.

    Verified before it is written: the stripped source must still parse.
    If it does not, the original is copied instead, so you always have a
    file that runs."""
    import ast
    source = slurp(path)
    stripped = strip_comments(source)
    try:
        ast.parse(stripped)
    except SyntaxError:
        stripped = source                      # never hand over a broken file
        if not quiet:
            print("  (could not strip safely - clean copy is identical)")

    if cfg:
        header = ("# %s - Information Security Lab\n"
                  "# %s%s | %s | %s signature | role-based access control\n"
                  "# generated %s\n\n"
                  % (cfg.get("system_name", "SecureSystem"),
                     cfg.get("cipher", ""),
                     "" if cfg.get("mode", "-") == "-"
                     else " / " + cfg["mode"],
                     cfg.get("hash", ""), cfg.get("signature", ""),
                     timestamp()))
        stripped = header + stripped

    out = clean_name(path)
    write_output(out, stripped)
    if not quiet:
        print("built %s  (%d lines, no comments)"
              % (out, stripped.count("\n")))
    return out



MODERN_SET = {"DES", "3DES", "AES-128", "AES-192", "AES-256"}

# cipher -> (pycryptodome module name, key size in bytes)
MODERN_INFO = {"DES": ("DES", 8), "3DES": ("DES3", 24), "AES-128": ("AES", 16),
               "AES-192": ("AES", 24), "AES-256": ("AES", 32)}

SIGN_IMPORTS = {
    "RSA": "from Crypto.PublicKey import RSA\n"
           "from Crypto.Signature import pkcs1_15\n"
           "from Crypto.Hash import SHA256",
    "ECDSA": "from Crypto.PublicKey import ECC\n"
             "from Crypto.Signature import DSS\n"
             "from Crypto.Hash import SHA256",
    "ELGAMAL": "import random\nimport math",
    "SCHNORR": "import random",
}


def lean_key_line(cipher, raw):
    """The settings line that defines `key`, in the plainest form that works."""
    upper = cipher.upper()
    if upper in MODERN_SET:
        size = MODERN_INFO[upper][1]
        text = raw if isinstance(raw, str) else raw.decode("latin-1")
        try:                                    # a hex string of the right size
            if len(bytes.fromhex(text)) == size:
                return 'key = bytes.fromhex("%s")' % text
        except ValueError:
            pass
        data = text.encode()
        data = (data + b"\0" * size)[:size]
        if upper == "3DES" and (data[:8] == data[8:16]
                                or data[8:16] == data[16:]):
            data = data[:8] + bytes([data[8] ^ 2]) + data[9:]
        if all(32 <= b < 127 for b in data):
            return 'key = b"%s"' % data.decode()
        return 'key = bytes.fromhex("%s")' % data.hex()
    if upper in ("ADDITIVE", "MULTIPLICATIVE"):
        return "key = %d" % int(raw)
    if upper == "AFFINE":
        if isinstance(raw, (tuple, list)):
            a, b = int(raw[0]), int(raw[1])
        else:
            a, b = [int(v) for v in
                    str(raw).replace("(", "").replace(")", "").split(",")]
        return "key = (%d, %d)" % (a, b)
    if upper == "HILL":
        if isinstance(raw, (list, tuple)):
            rows = [[int(v) for v in row] for row in raw]
        else:
            rows = [[int(v) for v in row.split(",")]
                    for row in str(raw).split(";")]
        return "key = %r" % rows
    return 'key = "%s"' % raw


def emit_lean(cfg, roles, out="answer.py"):
    """Write a compact, flat answer file for ONE configuration."""
    cipher = cfg["cipher"].upper()
    sig = cfg.get("signature", "RSA").upper()
    if sig == "NONE":
        sig = "RSA"
    modern = cipher in MODERN_SET
    mode = cfg.get("mode", "-") if modern else "-"
    if modern and mode not in MODERN_BODIES:
        mode = "ECB"
    hash_algo = cfg.get("hash", "sha256")

    imports = []
    if modern:
        module, _ = MODERN_INFO[cipher]
        imports.append("from Crypto.Cipher import %s" % module)
        imports.append("from Crypto.Util.Padding import pad, unpad")
        if mode != "ECB":
            imports.append("from Crypto.Random import get_random_bytes")
    imports.append(SIGN_IMPORTS[sig])

    role_lines = ",\n".join(
        '    "%s": [%s]' % (rid, ", ".join('"%s"' % p for p in perms))
        for rid, _label, perms in roles)
    read_only = roles[-1] if roles else ("hod", "HoD", [])

    parts = [LEAN_HEAD % {
        "name": cfg["system_name"], "cipher": cipher,
        "modetxt": "" if mode == "-" else " / " + mode,
        "hash": hash_algo, "sig": sig,
        "rolelist": ", ".join(r[1] for r in roles),
        "outfile": os.path.basename(out),
        "imports": "\n".join(imports),
        "keyline": lean_key_line(cipher, cfg["key"]),
        "roles": role_lines}]

    if modern:
        module, _ = MODERN_INFO[cipher]
        enc, dec = MODERN_BODIES[mode]
        parts.append(LEAN_MODERN % {
            "cipher": cipher, "mode": mode,
            "enc_body": enc % {"mod": module},
            "dec_body": dec % {"mod": module}})
    else:
        parts.append(LEAN_CLASSIC_HEAD % {"cipher": cipher})
        parts.append(LEAN_CIPHERS[cipher] % {})
        parts.append(LEAN_CLASSIC_TAIL)

    parts.append(LEAN_HASH_CUSTOM if hash_algo == "custom"
                 else LEAN_HASH % {"hash": hash_algo})
    parts.append(LEAN_SIGN[sig])
    parts.append(LEAN_BODY)
    parts.append(LEAN_MENU)
    parts.append(LEAN_DEMO % {
        "cipher": cipher, "modetxt": "" if mode == "-" else " / " + mode,
        "hash": hash_algo, "sig": sig,
        "demo_user": (roles[0][0][:3].upper() + "001") if roles else "U001",
        "read_only": read_only[1], "read_only_id": read_only[0]})

    text = "\n".join(p.strip("\n") + "\n" for p in parts)
    write_output(out, text)
    print("built %s  (%d lines, lean)" % (out, count_lines(out)))
    write_clean_twin(out, cfg)
    return out


def emit_answer(blocks, cfg, roles, out="answer.py"):
    """Write a standalone answer file with CONFIG/ROLES at the very top."""
    src = extract_blocks()
    names = [b for b in BLOCK_ORDER if b in set(blocks)]

    role_lines = []
    for rid, label, perms in roles:
        role_lines.append('    "%s": {"label": "%s",' % (rid, label))
        role_lines.append('%s"permissions": %s},'
                          % (" " * (len(rid) + 9), repr(perms)))

    head = [
        '"""',
        '%s - Information Security Lab' % cfg["system_name"],
        '',
        'Confidentiality : %s%s' % (cfg["cipher"],
                                    "" if cfg["mode"] == "-"
                                    else " / " + cfg["mode"]),
        'Integrity       : %s' % cfg["hash"],
        'Authenticity    : %s digital signatures' % cfg["signature"],
        'Access control  : role-based (%s)'
        % ", ".join(r[1] for r in roles),
        '',
        'Generated %s' % timestamp(),
        '"""',
        '',
        CONFIG_START,
        '# Change anything here and re-run - nothing else needs editing.',
        'CONFIG = {',
        '    "system_name": %r,' % cfg["system_name"],
        '    "cipher":      %r,' % cfg["cipher"],
        '    "mode":        %r,' % cfg["mode"],
        '    "key":         %s,' % _fmt_key(cfg["cipher"], cfg["key"]),
        '    "signature":   %r,' % cfg["signature"],
        '    "rsa_bits":    2048,',
        '    "hash":        %r,' % cfg["hash"],
        '    "sign_target": %r,' % cfg["sign_target"],
        '    "db_file":     "records.json",',
        '    "key_dir":     "keys",',
        '    "log_file":    "audit.log",',
        '}',
        '',
        'ROLES = {',
    ] + role_lines + [
        '}',
        CONFIG_END,
        '',
    ]

    parts = ["\n".join(head)]
    for n in names:
        parts.append(src[n].rstrip())
        parts.append("")
    if "TEMPLATE" in names:
        parts += [
            "",
            "# ============================ RUN =========================",
            "# python <file>        the menu",
            "# python <file> demo   whole flow, no typing",
            "# python <file> reset  clear records / keys / log",
            "if __name__ == '__main__':",
            "    import sys",
            "    _arg = sys.argv[1] if len(sys.argv) > 1 else ''",
            "    if _arg == 'reset':",
            "        reset_demo_files()",
            "    elif _arg == 'demo':",
            "        reset_demo_files()",
            "        SecureSystem().demo()",
            "    else:",
            "        SecureSystem().menu()",
            "",
        ]
    write_output(out, "\n".join(parts))
    write_clean_twin(out, cfg)          # answer_clean.py - the one you show
    return out


RUN_MARKER = "# ============================ RUN ===================="

# a signature function that proves a block is already present in a file
BLOCK_FINGERPRINT = {
    "CORE": "def read_input(", "CLASSIC_SUB": "def affine_encrypt(",
    "CLASSIC_POLY": "def vigenere_encrypt(",
    "CLASSIC_PLAYFAIR": "def playfair_encrypt(",
    "CLASSIC_HILL": "def hill_encrypt(",
    "CLASSIC_TRANS": "def transposition_encrypt(",
    "SYM": "def sym_encrypt(", "RSA": "def rsa_generate(",
    "ELGAMAL": "def elgamal_keygen(", "RABIN": "def rabin_keygen(",
    "DH": "def dh_keygen(", "ECC": "def ecc_keygen(",
    "HASH": "def hash_data(", "SIGN": "def rsa_sign(",
    "KMS": "class KeyManager", "ACCESS": "class RBAC",
    "SOCKET": "def send_msg(", "ATTACK": "def brute_force_additive(",
    "DISPATCH": "def encrypt_any(", "TEMPLATE": "class SecureSystem",
}


def _has_block(text, name):
    fp = BLOCK_FINGERPRINT.get(name)
    return bool(fp) and fp in text


def _inject_blocks(text, names):
    """Insert block source into an existing answer file, before the RUN part."""
    src = extract_blocks()
    add = "\n\n".join(src[n].rstrip() for n in names if n in src)
    if RUN_MARKER in text:
        head, tail = text.split(RUN_MARKER, 1)
        return head + add + "\n\n\n" + RUN_MARKER + tail
    return text.rstrip() + "\n\n\n" + add + "\n"


def _roles_from_text(text):
    """Read the roles out of an existing answer file so a rebuild keeps
    whatever you already set. Handles both shapes:
        lean  roles = {"student": ["upload"], ...}
        full  ROLES = {"student": {"label": ..., "permissions": [...]}, ...}
    Falls back to the default three."""
    for marker in ("roles = {", "ROLES = {"):
        if marker not in text:
            continue
        try:
            body = text.split(marker, 1)[1].split("\n}", 1)[0]
            ns = {}
            exec("data = {" + body + "\n}", ns)
            out = []
            for rid, value in ns["data"].items():
                if isinstance(value, dict):
                    out.append((rid, value["label"], value["permissions"]))
                else:
                    out.append((rid, rid.capitalize(), list(value)))
            if out:
                return out
        except Exception:
            continue
    return DEFAULT_ROLES

def reconfigure(path):
    """Re-run just the settings questions on an already-built answer file."""
    if not os.path.exists(path):
        print("no such file:", path)
        return None
    text = slurp(path)
    has_config = CONFIG_START in text and CONFIG_END in text
    has_settings = SETTINGS_START in text and SETTINGS_END in text
    if not (has_config or has_settings):
        print("%s has no settings block - edit it by hand, or rebuild with "
              "--wizard" % path)
        return None

    # A LEAN file contains only the one cipher it was built for, so changing
    # the cipher means regenerating it rather than patching CONFIG.
    is_lean = has_settings or ("def encrypt_data(" in text
                               and not _has_block(text, "DISPATCH"))
    print("\nReconfiguring %s (%s)"
          % (path, "lean file - it will be rebuilt" if is_lean
             else "blocks stay exactly as they are"))
    name = _ask("System name", "EduSecure")
    labels = ["%-15s (%s)" % (c[0], c[4]) for c in CIPHER_TABLE]
    ci = _ask_choice("Cipher", labels, "1")
    cipher, defkey, defmode, cblock, hint = CIPHER_TABLE[ci]
    key = _ask("Key (%s)" % hint, defkey)
    mode = "-"
    if cblock == "SYM":
        mode = ["ECB", "CBC", "CFB", "OFB", "CTR"][
            _ask_choice("Mode", ["ECB", "CBC", "CFB", "OFB", "CTR"], "1")]
    signature = SIG_TABLE[_ask_choice("Signature",
                                      [s[0] for s in SIG_TABLE], "1")][0]
    hashalgo = HASH_TABLE[_ask_choice("Hash", HASH_TABLE, "1")]

    if is_lean:
        # keep the roles that are already in the file
        roles = _roles_from_text(text)
        cfg = {"system_name": name, "cipher": cipher, "mode": mode,
               "key": key, "signature": signature if signature != "NONE"
               else "RSA", "hash": hashalgo, "sign_target": "cipher"}
        emit_lean(cfg, roles, path)
        print("rebuilt %s -> %s%s + %s + %s"
              % (path, cipher, "" if mode == "-" else "/" + mode,
                 cfg["signature"], hashalgo))
        print("run it with:  python %s      (or: python %s demo)"
              % (path, path))
        return path

    # a new cipher / signature may need a block this file does not have yet
    needed = [cblock] + dict(SIG_TABLE).get(signature, [])
    missing = [b for b in needed
               if ("# BLOCK %s" % b) not in text and not _has_block(text, b)]
    if missing:
        print("\n  This file is missing the block(s):", ", ".join(missing))
        if _ask("  Add them now? (y/n)", "y").lower().startswith("y"):
            text = _inject_blocks(text, missing)
            print("  added:", ", ".join(missing))
        else:
            print("  WARNING: %s will fail without them." % cipher)

    old = text.split(CONFIG_START)[1].split(CONFIG_END)[0]
    roles_part = "ROLES = {" + old.split("ROLES = {")[1] if "ROLES = {" in old \
        else ""
    new = "\n".join([
        '',
        '# Change anything here and re-run - nothing else needs editing.',
        'CONFIG = {',
        '    "system_name": %r,' % name,
        '    "cipher":      %r,' % cipher,
        '    "mode":        %r,' % mode,
        '    "key":         %s,' % _fmt_key(cipher, key),
        '    "signature":   %r,' % (signature if signature != "NONE"
                                    else "RSA"),
        '    "rsa_bits":    2048,',
        '    "hash":        %r,' % hashalgo,
        '    "sign_target": "cipher",',
        '    "db_file":     "records.json",',
        '    "key_dir":     "keys",',
        '    "log_file":    "audit.log",',
        '}',
        '',
        roles_part.rstrip(),
        '',
    ])
    write_output(path, text.split(CONFIG_START)[0] + CONFIG_START + new
                 + CONFIG_END + text.split(CONFIG_END, 1)[1])
    write_clean_twin(path)              # keep the comment-free copy in step
    print("\nupdated %s -> %s%s + %s + %s"
          % (path, cipher, "" if mode == "-" else "/" + mode,
             signature, hashalgo))
    print("run it with:  python %s      (or: python %s demo)" % (path, path))
    return path

def check_environment():
    """Run this FIRST in the 15-minute window."""
    import sys
    print("=" * 60)
    print("  ENVIRONMENT CHECK")
    print("=" * 60)
    ok = True
    print("python           :", sys.version.split()[0],
          "OK" if sys.version_info >= (3, 6) else "TOO OLD")
    print("interpreter      :", sys.executable)
    in_venv = (hasattr(sys, "real_prefix")
               or sys.prefix != getattr(sys, "base_prefix", sys.prefix))
    print("virtualenv       :", "active" if in_venv else
          "NOT active (fine, but pip installs go system-wide)")

    for mod, pipname, needed_for in (
            ("Crypto", "pycryptodome",
             "DES / AES / RSA / ECC / signatures - the only one needed"),):
        try:
            __import__(mod)
            print("%-16s : installed" % pipname)
        except ImportError:
            ok = False
            print("%-16s : MISSING  (needed for %s)" % (pipname, needed_for))
            print("                   FIX:  pip install " + pipname)

    try:
        import matplotlib          # noqa: F401
        print("matplotlib       : installed (graphs available)")
    except ImportError:
        print("matplotlib       : missing (only needed for graphs)")
        print("                   FIX:  pip install matplotlib")

    s = socket.socket()
    try:
        s.bind(("localhost", 0))
        print("sockets          : working (port %d)" % s.getsockname()[1])
    except Exception as ex:
        ok = False
        print("sockets          : FAILED", ex)
    finally:
        s.close()

    try:
        p = write_output("_envcheck.tmp", b"x")
        os.remove(p)
        print("file write       : working")
    except Exception as ex:
        ok = False
        print("file write       : FAILED", ex)

    print("playsheet path   :", _source_path())
    print("blocks found     :", len(extract_blocks()))
    print("-" * 60)
    print("RESULT:", "READY" if ok else "FIX THE ITEMS MARKED MISSING/FAILED")
    if not ok:
        print("\nOne-shot fix:")
        print("   python -m pip install pycryptodome matplotlib")
        print("If pip refuses ('externally managed environment'):")
        print("   python -m pip install --break-system-packages pycryptodome")
        print("Or make a clean environment first:  python playsheet.py --venv")
    print("=" * 60)
    return ok


def venv_help():
    """Print the exact commands to make and use a virtual environment."""
    import sys
    print("=" * 62)
    print("  VIRTUAL ENVIRONMENT - do this first, before installing anything")
    print("=" * 62)
    print("""
  1. create it (once, in your working folder)
         python -m venv .venv

  2. activate it - EVERY new terminal needs this
         Windows PowerShell   .venv\\Scripts\\Activate.ps1
         Windows cmd.exe      .venv\\Scripts\\activate.bat
         mac / linux          source .venv/bin/activate
     Your prompt now starts with (.venv).

  3. install the libraries
         python -m pip install --upgrade pip
         python -m pip install pycryptodome matplotlib

  4. prove it worked
         python playsheet.py --check       wants RESULT: READY
         python playsheet.py --selftest    wants 113/113 passed

  If PowerShell blocks activation with a script-execution error:
         Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
  and run the activate command again.

  If you cannot create a venv at all, skip it and just run
         python -m pip install --break-system-packages pycryptodome
  Everything works the same, the packages just install system-wide.

  NOTE: install "pycryptodome", never "pycrypto" - the old one is broken
  and the import is 'Crypto' in both cases, which causes real confusion.
""")
    print("  this interpreter :", sys.executable)
    print("=" * 62)


def setup_install():
    """pip install everything (use while the internet is still on)."""
    import subprocess
    import sys
    pkgs = ["pycryptodome", "matplotlib"]
    print("installing:", " ".join(pkgs))
    for p in pkgs:
        for cmd in ([sys.executable, "-m", "pip", "install", p],
                    [sys.executable, "-m", "pip", "install",
                     "--break-system-packages", p]):
            try:
                r = subprocess.run(cmd, capture_output=True, text=True)
                if r.returncode == 0:
                    print("  %-16s OK" % p)
                    break
            except Exception:
                continue
        else:
            print("  %-16s FAILED - try manually: pip install %s" % (p, p))
    check_environment()


def selftest(verbose=True):
    """Prove every block works. Run this in the 15-minute window."""
    checks, fails = [], []

    def chk(name, cond):
        checks.append((name, bool(cond)))
        if not cond:
            fails.append(name)

    m = "Information Security"
    chk("additive", additive_decrypt(additive_encrypt(m, 20), 20)
        == clean_text(m))
    chk("multiplicative", multiplicative_decrypt(
        multiplicative_encrypt(m, 15), 15) == clean_text(m))
    chk("affine", affine_decrypt(affine_encrypt(m, 15, 20), 15, 20)
        == clean_text(m))
    chk("vigenere", vigenere_decrypt(vigenere_encrypt(m, "dollars"),
                                     "dollars") == clean_text(m))
    chk("autokey int", autokey_decrypt(autokey_encrypt(m, 7), 7)
        == clean_text(m))
    chk("autokey word", autokey_decrypt(autokey_encrypt(m, "HEALTH"),
                                        "HEALTH") == clean_text(m))
    chk("playfair", playfair_decrypt(playfair_encrypt(m, "GUIDANCE"),
                                     "GUIDANCE").replace("X", "")
        .startswith("INFORMATION"))
    K = [[3, 3], [2, 7]]
    chk("hill", hill_decrypt(hill_encrypt(m, K), K).startswith(clean_text(m)))
    chk("transposition", transposition_decrypt(
        transposition_encrypt(m, "3142"), "3142").startswith(clean_text(m)))

    for a in SYM_ALGOS:
        for md in ("ECB", "CBC", "CFB", "OFB", "CTR"):
            try:
                ct, iv = sym_encrypt(m, "A1B2C3D4", a, md)
                good = sym_decrypt(ct, "A1B2C3D4", a, md, iv) == m.encode()
            except Exception:
                good = False
            chk("%s/%s" % (a, md), good)
    c, n, t = aes_gcm_encrypt(m, "k")
    chk("AES-GCM", aes_gcm_decrypt(c, "k", n, t) == m.encode())

    pub, priv, _ = rsa_keygen_textbook()
    chk("RSA textbook", rsa_decrypt_textbook(
        rsa_encrypt_textbook(m, pub), priv) == m.encode())
    k, pk = rsa_generate(2048)
    chk("RSA-OAEP", rsa_decrypt(rsa_encrypt(m, pk), k) == m.encode())
    chk("RSA hybrid", rsa_hybrid_decrypt(
        *rsa_hybrid_encrypt(b"Z" * 4096, pk), k) == b"Z" * 4096)
    ep, ex = elgamal_keygen()
    chk("ElGamal", elgamal_decrypt(elgamal_encrypt(m, ep), ex, ep)
        == m.encode())
    rn, rpq = rabin_keygen(32)
    chk("Rabin", rabin_decrypt(rabin_encrypt(m, rn), rpq) == m.encode())
    a1, A1 = dh_keygen(23, 5)
    b1, B1 = dh_keygen(23, 5)
    chk("Diffie-Hellman", dh_shared(B1, a1, 23) == dh_shared(A1, b1, 23))
    pr, pu = ecc_keygen()
    e2, n2, c2 = ecc_encrypt(m, pu)
    chk("ECC", ecc_decrypt(e2, n2, c2, pr) == m.encode())

    chk("custom hash", len(hash_data(m, "custom")) == 8)
    chk("sha256", hash_data(m) == hashlib.sha256(m.encode()).hexdigest())
    chk("hmac", hmac_verify(m, "k", hmac_digest(m, "k")))

    chk("RSA sign", rsa_verify(m, rsa_sign(m, k), pk)
        and not rsa_verify(m + "!", rsa_sign(m, k), pk))
    chk("RSA-PSS", rsa_verify(m, rsa_sign(m, k, "pss"), pk, "pss"))
    ds = ecdsa_sign(m, pr)
    chk("ECDSA", ecdsa_verify(m, ds, pu) and not ecdsa_verify(m + "!", ds, pu))
    es = elgamal_sign(m, ep, ex)
    chk("ElGamal sign", elgamal_verify(m, es, ep)
        and not elgamal_verify(m + "!", es, ep))
    sp, sx = schnorr_keygen()
    ss = schnorr_sign(m, sp, sx)
    chk("Schnorr sign", schnorr_verify(m, ss, sp)
        and not schnorr_verify(m + "!", ss, sp))

    chk("socket integrity", socket_integrity_demo(m) is True)
    chk("socket tamper", socket_integrity_demo(m, tamper=True) is False)
    chk("socket multipart", socket_multipart_demo() is True)
    chk("socket signature", socket_signature_demo(m) is True)
    chk("secure channel", socket_secure_channel_demo(m) is True)

    chk("affine attack", affine_known_plaintext("a", "G", "b", "L") == (5, 6))
    chk("shift attack", shift_from_pair("yes", "CIW") == 4)
    chk("RSA factoring", factor_rsa_small(3233) in ((53, 61), (61, 53)))

    km = KeyManager("RSA", 1024, logfile="_st.log")
    km.generate("E1", verbose=False)
    chk("KMS distribute", km.distribute("E1", True) is not None)
    km.revoke("E1", "test")
    chk("KMS revoke blocks", km.distribute("E1") is None)
    chk("RBAC", RBAC({"a": ["x"]}).allowed("a", "x")
        and not RBAC({"a": ["x"]}).allowed("a", "y"))
    chk("Bell-LaPadula", bell_lapadula("SECRET", "PUBLIC", "read")
        and not bell_lapadula("PUBLIC", "SECRET", "read"))

    # every cipher inside the scenario template
    tmp = {"db_file": "_st_rec.json", "key_dir": "_st_keys",
           "log_file": "_st_audit.log"}
    combos = [("DES", "ECB", "A1B2C3D4"),
              ("AES-256", "CBC", "0123456789ABCDEF0123456789ABCDEF"),
              ("HILL", "-", [[3, 3], [2, 7]]),
              ("VIGENERE", "-", "dollars"),
              ("PLAYFAIR", "-", "GUIDANCE"),
              ("AFFINE", "-", "15,20"),
              ("TRANSPOSITION", "-", "3142")]
    for cip, md, key in combos:
        for sg in ("RSA", "ELGAMAL"):
            cfg = dict(tmp)
            cfg.update(cipher=cip, mode=md, key=key, signature=sg)
            reset_demo_files(cfg)
            sysm = SecureSystem(cfg)
            rec = sysm.upload("U", "Secret Data", verbose=False)
            _, r1 = sysm.verify_record(rec["id"], verbose=False)
            sysm.tamper(rec["id"], verbose=False)
            _, r2 = sysm.verify_record(rec["id"], verbose=False)
            chk("template %s+%s" % (cip, sg),
                r1["signature_valid"] and r1["integrity_ok"]
                and not r2["signature_valid"] and not r2["integrity_ok"])
    reset_demo_files(tmp)

    # the block builder and the interactive builder's file emitter
    built = build_answer("exam", "_st_answer.py", quiet=True)
    chk("builder output", built and os.path.exists(built))
    if built:
        import subprocess
        import sys
        r = subprocess.run([sys.executable, "-c",
                            "import ast;ast.parse(open('_st_answer.py')"
                            ".read())"], capture_output=True)
        chk("built file parses", r.returncode == 0)
        tidy(built, clean_name(built))

    roles = [("student", "Student", ["upload", "view_own"]),
             ("faculty", "Faculty", ["decrypt_verify", "tamper_test"]),
             ("hod", "HoD", ["view_hashes"])]
    emitted = 0
    for cip, key, md, blk in (("DES", "A1B2C3D4", "ECB", "SYM"),
                              ("HILL", "3,3;2,7", "-", "CLASSIC_HILL"),
                              ("VIGENERE", "dollars", "-", "CLASSIC_POLY")):
        cfg = {"system_name": "T", "cipher": cip, "mode": md, "key": key,
               "signature": "RSA", "hash": "sha256", "sign_target": "cipher"}
        f = emit_answer(["CORE", "SYM", "HASH", "RSA", "SIGN", "DISPATCH",
                         "TEMPLATE", blk], cfg, roles, "_st_w.py")
        import subprocess
        import sys
        r = subprocess.run([sys.executable, "-c",
                            "import ast;ast.parse(open('_st_w.py').read())"],
                           capture_output=True)
        txt = slurp(f)
        good = (r.returncode == 0 and CONFIG_START in txt
                and ("'%s'" % cip) in txt and _has_block(txt, blk))
        chk("wizard emits %s" % cip, good)
        emitted += 1
    # injecting a block that is missing from an existing file
    txt = slurp("_st_w.py")
    chk("block detect", _has_block(txt, "TEMPLATE")
        and not _has_block(txt, "RABIN"))
    txt2 = _inject_blocks(txt, ["RABIN"])
    chk("block inject", _has_block(txt2, "RABIN"))
    write_output("_st_w.py", txt2)
    import subprocess
    import sys
    r = subprocess.run([sys.executable, "-c",
                        "import ast;ast.parse(open('_st_w.py').read())"],
                       capture_output=True)
    chk("injected file parses", r.returncode == 0)
    tidy("_st_w.py", clean_name("_st_w.py"))

    # ---- new manual-coverage blocks --------------------------------------
    chk("rail fence", rail_fence_decrypt(rail_fence_encrypt(m, 3), 3)
        == clean_text(m))
    rk, nr = aes_round_keys(make_key("FEDCBA9876543210FEDCBA98", 24),
                            verbose=False)
    chk("aes key expansion", nr == 12 and len(rk) == 13 and len(rk[0]) == 16)
    chk("aes-128 rounds", aes_round_keys(b"0" * 16, verbose=False)[1] == 10)
    chk("aes-256 rounds", aes_round_keys(b"0" * 32, verbose=False)[1] == 14)
    ff = fermat_factor(1000003 * 1000033, verbose=False)
    chk("fermat factor", ff == (1000003, 1000033))
    chk("shared prime", shared_prime_attack(7919 * 7907, 7919 * 7901)[0] == 7919)
    rec = recover_rsa_private(3233, 17, verbose=False)
    chk("rsa key recovery", rec and 17 * rec["d"] % rec["phi"] == 1)
    tbl = collisions_truncated(algos=("sha256",), bits=(16,), count=1500)
    chk("truncated collisions", tbl["sha256"][0] > 0)
    _kp, _ = rsa_generate(1024)
    _sig = rsa_sign_raw("Alice", _kp.n, _kp.d)
    chk("raw rsa signature", rsa_verify_raw(_sig, _kp.n, _kp.e)[1] == b"Alice")
    chk("hex sig format", parse_hex_sig(format_hex_sig(b"\xc8\x93")) == b"\xc8\x93")
    chk("hexs int", hexs(4660) == "1234" and hexs(255) == "ff")
    chk("hexs pads odd", hexs(0xabc) == "0abc")
    chk("hexs bytes", hexs(b"\xc8\x93") == "c893")
    chk("hexs grouping", hexs(b"\xc8\x93\x01", 2) == "c8 93 01")
    chk("unhexs round trip", unhexs(hexs(123456789)) == 123456789)
    chk("sig_hex pair", sig_hex((255, 16)) == "r=ff s=10")
    chk("strip removes comments",
        "#" not in strip_comments("x = 1  # note\ny = 2\n"))
    chk("strip keeps code",
        strip_comments("x = 1  # note\ny = 2\n").strip() == "x = 1\ny = 2")
    chk("strip spares a hash inside a string",
        "#" in strip_comments('x = "a # b"\ny = 2\n'))
    chk("strip drops docstrings",
        '"""' not in strip_comments('def f():\n    """doc"""\n    return 1\n'))
    chk("strip spares a docstring-only body",
        '"""' in strip_comments('def f():\n    """doc"""\n'))
    # REGRESSION GUARD: a newer Python shows invalid escape sequences as a
    # visible SyntaxWarning. Prove this file and its output are clean.
    import warnings as _warn
    with _warn.catch_warnings(record=True) as _w:
        _warn.simplefilter("always")
        compile(slurp(_source_path()),
                "playsheet.py", "exec")
        chk("playsheet.py has no invalid escapes",
            not [x for x in _w if "escape" in str(x.message)])

    # REGRESSION GUARD: an unclosed file handle is what makes Windows refuse
    # the next delete, so prove the whole run leaks none.
    with _warn.catch_warnings(record=True) as _w:
        _warn.simplefilter("always")
        _t = "_st_rw.py"
        emit_lean({"system_name": "T", "cipher": "DES", "mode": "ECB",
                   "key": "A1B2C3D4", "signature": "RSA", "hash": "sha256",
                   "sign_target": "cipher"}, DEFAULT_ROLES, _t)
        count_lines(_t)
        slurp(_t)
        tidy(_t, clean_name(_t))
        chk("no unclosed file handles",
            not [x for x in _w if x.category is ResourceWarning])

    # REGRESSION GUARD: teardown must never raise, even on a locked path.
    try:
        tidy("_st_nonexistent.py", "_st_nonexistent_dir")
        chk("tidy survives missing paths", True)
    except Exception:
        chk("tidy survives missing paths", False)

    chk("safe_text keeps real text", safe_text(b"marks 9/10")
        == "marks 9/10")
    chk("safe_text tames garbage",
        safe_text(bytes([0x93, 0xfe, 0x41])) == "..A")

    # ---- lean emitter: every cipher and every signature scheme -----------
    import subprocess
    import sys
    lean_ok = 0
    lean_cases = [(c[0], "RSA", "sha256") for c in CIPHER_TABLE] + \
                 [("AES-256", sg, "sha256") for sg in
                  ("ECDSA", "ELGAMAL", "SCHNORR")] + \
                 [("AES-128", "RSA", h) for h in ("md5", "sha512", "custom")]
    for cip, sg, hs in lean_cases:
        row = next(c for c in CIPHER_TABLE if c[0] == cip)
        cfg = {"system_name": "T", "cipher": cip, "mode": row[2],
               "key": row[1], "signature": sg, "hash": hs,
               "sign_target": "cipher"}
        d = "_st_lean"
        if os.path.isdir(d):
            shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d, exist_ok=True)
        f = os.path.join(d, "a.py")
        emit_lean(cfg, DEFAULT_ROLES, f)
        r = subprocess.run([sys.executable, "a.py", "demo"], cwd=d,
                           capture_output=True, text=True,
                           encoding="utf-8", errors="replace")
        good = (r.returncode == 0 and "Integrity  : OK" in r.stdout
                and "Signature  : VALID" in r.stdout
                and "FAILED - record modified" in r.stdout
                and "ACCESS DENIED" in r.stdout)
        chk("lean %s/%s/%s" % (cip, sg, hs), good)

        # the comment-free twin must behave exactly the same
        rc = subprocess.run([sys.executable, "a_clean.py", "demo"], cwd=d,
                            capture_output=True, text=True,
                            encoding="utf-8", errors="replace")
        chk("clean twin %s/%s/%s" % (cip, sg, hs),
            rc.returncode == 0
            and "Integrity  : OK" in rc.stdout
            and "Signature  : VALID" in rc.stdout
            and "FAILED - record modified" in rc.stdout)
        lean_ok += bool(good)
        # REGRESSION GUARD: a Windows console is cp1252 and used to crash on
        # the garbage a tampered record decrypts to. Re-run one build with
        # that encoding forced, to prove the output stays printable.
        if cip in ("AES-256", "DES"):
            env = dict(os.environ, PYTHONIOENCODING="cp1252")
            r2 = subprocess.run([sys.executable, "a.py", "demo"], cwd=d,
                                capture_output=True, text=True, env=env,
                                encoding="utf-8", errors="replace")
            chk("lean %s on a cp1252 console" % cip,
                r2.returncode == 0
                and "FAILED - record modified" in r2.stdout)
        shutil.rmtree(d, ignore_errors=True)
    if verbose:
        print("lean answer files: %d/%d built, ran and detected tampering"
              % (lean_ok, len(lean_cases)))

    tidy("_st.log", "_st_lean", "_st_keys", "_st.json")

    passed = sum(1 for _, o in checks if o)
    print("\n" + "=" * 54)
    print("SELF TEST : %d/%d passed" % (passed, len(checks)))
    if fails:
        print("FAILED    :", ", ".join(fails))
    else:
        print("Every block works. You are ready.")
    print("=" * 54)
    if verbose and fails:
        for nm, o in checks:
            if not o:
                print("  x", nm)
    return passed, fails


def quick_demo():
    """Show the same scenario running on a modern AND a classical cipher."""
    for cfg in ({"cipher": "DES", "mode": "ECB", "key": "A1B2C3D4"},
                {"cipher": "HILL", "mode": "-", "key": [[3, 3], [2, 7]]}):
        reset_demo_files()
        SecureSystem(cfg).demo()
    reset_demo_files()


DEFAULT_ROLES = [("student", "Student", ["upload", "view_own"]),
                 ("faculty", "Faculty", ["decrypt_verify", "view_all",
                                         "tamper_test"]),
                 ("hod", "HoD", ["view_hashes", "audit"])]


def lean_quick(cipher="DES", out="answer.py", name=None, sig="RSA",
               hashalgo="sha256", mode=None, key=None, roles=None):
    """One-liner build with no questions:
           python playsheet.py --lean AES-256 -o answer.py
    Everything can still be changed in the SETTINGS block afterwards."""
    cipher = cipher.upper()
    row = next((c for c in CIPHER_TABLE if c[0] == cipher), None)
    if row is None:
        print("unknown cipher: %s" % cipher)
        print("choose from:", ", ".join(c[0] for c in CIPHER_TABLE))
        return None
    cfg = {"system_name": name or "SecureSystem", "cipher": cipher,
           "mode": mode or row[2], "key": key if key is not None else row[1],
           "signature": sig.upper(), "hash": hashalgo, "sign_target": "cipher"}
    path = emit_lean(cfg, roles or DEFAULT_ROLES, out)
    print("   cipher %s%s | hash %s | signature %s"
          % (cipher, "" if cfg["mode"] == "-" else " / " + cfg["mode"],
             hashalgo, sig.upper()))
    print("   edit the SETTINGS block at the top to change anything.")
    print("   run:  python %s demo    (no typing)" % out)
    print("   %s is the same program without comments." % clean_name(out))
    return path


def compare_sizes(tmp="_size_check.py"):
    """Show how much smaller the lean output is - useful once, before the exam."""
    print("\n%-28s %8s" % ("output", "lines"))
    print("-" * 38)
    emit_lean({"system_name": "X", "cipher": "DES", "mode": "ECB",
               "key": "A1B2C3D4", "signature": "RSA", "hash": "sha256",
               "sign_target": "cipher"}, DEFAULT_ROLES, tmp)
    lean_n = count_lines(tmp)
    build_answer("exam", tmp, quiet=True)
    full_n = count_lines(tmp)
    tidy(tmp, clean_name(tmp))
    print("%-28s %8d" % ("lean (DES + RSA + sha256)", lean_n))
    print("%-28s %8d" % ("full --build exam", full_n))
    print("%-28s %8.0f%%" % ("reduction", 100.0 * (full_n - lean_n) / full_n))
    return lean_n, full_n


def main():
    import sys
    args = sys.argv[1:]

    if "--check" in args:
        check_environment()
        return
    if "--setup" in args:
        setup_install()
        return
    if "--venv" in args:
        venv_help()
        return
    if "--selftest" in args:
        selftest()
        return
    if "--blocks" in args:
        list_blocks()
        return
    if "--demo" in args:
        quick_demo()
        return
    if "--wizard" in args:
        out = args[args.index("-o") + 1] if "-o" in args else "answer.py"
        wizard(out, full="--full" in args)
        return
    if "--lean" in args:
        i = args.index("--lean")
        preset = args[i + 1] if len(args) > i + 1 and \
            not args[i + 1].startswith("-") else "DES"
        out = args[args.index("-o") + 1] if "-o" in args else "answer.py"
        lean_quick(preset, out)
        return
    if "--reconfigure" in args:
        i = args.index("--reconfigure")
        reconfigure(args[i + 1] if len(args) > i + 1 else "answer.py")
        return
    if "--build" in args:
        i = args.index("--build")
        sel = args[i + 1] if len(args) > i + 1 else "exam"
        out = args[args.index("-o") + 1] if "-o" in args else "answer.py"
        build_answer(sel, out)
        return
    if "--compare" in args:
        compare_sizes()
        return

    print(__doc__)
    print("  python playsheet.py --wizard         INTERACTIVE BUILDER (lean)")
    print("  python playsheet.py --wizard --full  same, but paste every block")
    print("  python playsheet.py --lean AES-256 -o answer.py   no questions")
    print("  python playsheet.py --reconfigure answer.py   change settings")
    print("  python playsheet.py --check          environment check")
    print("  python playsheet.py --venv           venv + install instructions")
    print("  python playsheet.py --setup          pip install everything")
    print("  python playsheet.py --selftest       prove every block works")
    print("  python playsheet.py --blocks         list block names")
    print("  python playsheet.py --build exam -o answer.py")
    print("  python playsheet.py --demo           watch a scenario run")

    if sys.stdin.isatty():
        try:
            if _ask("\nStart the interactive builder now? (y/n)",
                    "y").lower().startswith("y"):
                wizard()
        except (EOFError, KeyboardInterrupt):
            print()


if __name__ == "__main__":
    main()
