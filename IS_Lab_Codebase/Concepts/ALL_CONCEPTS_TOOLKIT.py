"""
=============================================================================
 ALL_CONCEPTS_TOOLKIT.py  -  EVERY CONCEPT IN ONE IMPORTABLE FILE
=============================================================================

This is the single file to copy into an exam answer folder.

    from ALL_CONCEPTS_TOOLKIT import *

...and you instantly have every cipher, hash, signature, key-management and
access-control helper used anywhere in Labs 1-6.

It is auto-assembled from the Concepts/c01..c13 files, so the code is
identical - read those files for the full comments and the per-concept demos.

QUICK INDEX (search for the marker lines "### FROM c0x")
  c12  conversions, JsonStore, timestamps, padding, pretty printing
  c01  classical ciphers: additive/multiplicative/affine/Vigenere/autokey/
       Playfair/Hill/transposition + brute-force attacks
  c02  DES, 3DES, AES (ECB/CBC/CFB/OFB/CTR), make_key, AES key expansion
  c03  RSA: library + textbook, hybrid encryption, Fermat factoring attack
  c04  ElGamal encrypt/sign, Schnorr sign
  c05  ECC: ECDH, ECIES encrypt, ECDSA, raw point arithmetic
  c06  Rabin cryptosystem
  c07  Diffie-Hellman key exchange
  c08  hashing: sha256/md5/sha1, custom djb2 hash, HMAC, collision tests
  c09  digital signatures: RSA / DSA / ECDSA / textbook, CIA-triad helper
  c10  key management service (generate/distribute/revoke/renew/store/audit)
  c11  access control: RBAC, DAC matrix, Bell-LaPadula, time-limited grants
  c13  socket client/server with length-framed messages
=============================================================================
"""

import base64, hashlib, hmac, json, math, os, random, socket, string, struct, sys, time
from datetime import datetime, timedelta

from Crypto.Cipher import DES, DES3, AES, PKCS1_OAEP
from Crypto.PublicKey import RSA, DSA, ECC
from Crypto.Signature import pkcs1_15, pss, DSS
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2



# ==========================================================================
### FROM c12_conversions_and_storage.py
# ==========================================================================

def s2b(s):
    """str -> bytes"""
    return s.encode("utf-8")


def b2s(b):
    """bytes -> str (use errors='replace' if the bytes are not real text)"""
    return b.decode("utf-8", errors="replace")


def b2hex(b):
    return b.hex()                       # b'\xa1\xb2' -> 'a1b2'


def hex2b(h):
    return bytes.fromhex(h.replace(" ", "").replace("0x", ""))


def hex_spaced(b):
    """'0xa1 0xb2 ...' - the format the Lab 6 manual uses for signatures."""
    return " ".join(f"0x{x:02x}" for x in b)


def parse_spaced_hex(text):
    """'0xc8 0x93 ...' -> bytes"""
    return bytes(int(t, 16) for t in text.split())


def b2b64(b):
    return base64.b64encode(b).decode()


def b642b(s):
    return base64.b64decode(s)


def b2i(b):
    return int.from_bytes(b, "big")


def i2b(i):
    return i.to_bytes((i.bit_length() + 7) // 8 or 1, "big")


def to_binary(data):
    """bytes or str -> '01000001 01000010' """
    b = s2b(data) if isinstance(data, str) else data
    return " ".join(f"{x:08b}" for x in b)


def from_binary(bits):
    bits = bits.replace(" ", "")
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))


def xor_bytes(a, b):
    """XOR two byte strings (repeats b if it is shorter) - the core of OTP."""
    return bytes(x ^ b[i % len(b)] for i, x in enumerate(a))


def count_set_bits(b):
    return sum(bin(x).count("1") for x in b)


def hamming_distance(a, b):
    """Number of differing bits - used to show the avalanche effect."""
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def pkcs7_pad(data, block=8):
    n = block - (len(data) % block)
    return data + bytes([n]) * n             # pad byte value = number of pad bytes


def pkcs7_unpad(data):
    return data[:-data[-1]]


def now():
    """Timestamp string - questions always ask to store timestamps."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class JsonStore:
    """Dead-simple JSON 'database'. Bytes are stored base64-encoded.

    usage:
        db = JsonStore("records.json")
        db.add("records", {"user": "kavy", "ct": b2b64(ct), "ts": now()})
        for r in db.all("records"): print(r)
    """

    def __init__(self, path="store.json"):
        self.path = path
        self.data = {}
        if os.path.exists(path):
            with open(path) as f:
                self.data = json.load(f)

    def save(self):
        with open(self.path, "w") as f:
            json.dump(self.data, f, indent=2)

    def add(self, table, record):
        self.data.setdefault(table, []).append(record)
        self.save()
        return record

    def all(self, table):
        return self.data.get(table, [])

    def find(self, table, **filters):
        return [r for r in self.all(table)
                if all(r.get(k) == v for k, v in filters.items())]

    def clear(self, table=None):
        if table:
            self.data.pop(table, None)
        else:
            self.data = {}
        self.save()


def write_bytes(path, data):
    with open(path, "wb") as f:
        f.write(data)


def read_bytes(path):
    with open(path, "rb") as f:
        return f.read()


def write_text(path, text):
    with open(path, "w") as f:
        f.write(text)


def read_text(path):
    with open(path) as f:
        return f.read()


def banner(title, width=64):
    print("\n" + "=" * width)
    print(title.center(width))
    print("=" * width)


def field(label, value, width=18):
    print(f"{label:<{width}}: {value}")


def short(x, n=60):
    """Trim long hex so the screen stays readable."""
    s = x if isinstance(x, str) else str(x)
    return s if len(s) <= n else s[:n] + "..."


# ==========================================================================
### FROM c01_classical_ciphers.py
# ==========================================================================

def clean(text):
    """Keep only A-Z letters, uppercase them, drop spaces/punctuation.
    Manual always says 'ignore the space between words' -> use this first."""
    return "".join(ch for ch in text.upper() if ch.isalpha())


def to_nums(text):
    """'ABC' -> [0,1,2]   (A=0 ... Z=25)"""
    return [ord(ch) - 65 for ch in text]


def to_text(nums):
    """[0,1,2] -> 'ABC'"""
    return "".join(chr(n % 26 + 65) for n in nums)


def mod_inverse(a, m):
    """Find x such that (a*x) % m == 1.  Needed for multiplicative/affine/Hill.
    Brute force over 0..m-1 is fine because m is small (26)."""
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None                      # no inverse => gcd(a,m) != 1


def egcd(a, b):
    """Extended Euclid: returns (g, x, y) with a*x + b*y = g = gcd(a,b).
    Use this instead of mod_inverse when numbers are big (RSA etc.)."""
    if b == 0:
        return (a, 1, 0)
    g, x, y = egcd(b, a % b)
    return (g, y, x - (a // b) * y)


def additive_encrypt(plaintext, key):
    return to_text([(p + key) % 26 for p in to_nums(clean(plaintext))])


def additive_decrypt(ciphertext, key):
    return to_text([(c - key) % 26 for c in to_nums(clean(ciphertext))])


def multiplicative_encrypt(plaintext, key):
    return to_text([(p * key) % 26 for p in to_nums(clean(plaintext))])


def multiplicative_decrypt(ciphertext, key):
    k_inv = mod_inverse(key, 26)          # need inverse of key to undo multiply
    return to_text([(c * k_inv) % 26 for c in to_nums(clean(ciphertext))])


def affine_encrypt(plaintext, a, b):
    return to_text([(a * p + b) % 26 for p in to_nums(clean(plaintext))])


def affine_decrypt(ciphertext, a, b):
    a_inv = mod_inverse(a, 26)
    return to_text([(a_inv * (c - b)) % 26 for c in to_nums(clean(ciphertext))])


def vigenere_encrypt(plaintext, keyword):
    p = to_nums(clean(plaintext))
    k = to_nums(clean(keyword))
    # k[i % len(k)] -> repeat the keyword cyclically
    return to_text([(p[i] + k[i % len(k)]) % 26 for i in range(len(p))])


def vigenere_decrypt(ciphertext, keyword):
    c = to_nums(clean(ciphertext))
    k = to_nums(clean(keyword))
    return to_text([(c[i] - k[i % len(k)]) % 26 for i in range(len(c))])


def autokey_encrypt(plaintext, key):
    """key is a NUMBER (e.g. 7). Manual's Lab-1 Q2b uses key = 7."""
    p = to_nums(clean(plaintext))
    stream = [key] + p[:-1]               # first key, then plaintext shifted by 1
    return to_text([(p[i] + stream[i]) % 26 for i in range(len(p))])


def autokey_decrypt(ciphertext, key):
    c = to_nums(clean(ciphertext))
    p = []
    prev = key                            # first keystream value is the key
    for ch in c:
        val = (ch - prev) % 26
        p.append(val)
        prev = val                        # recovered letter becomes next key
    return to_text(p)


def autokey_word_encrypt(plaintext, keyword):
    """Variant where the key is a WORD instead of a number."""
    p = to_nums(clean(plaintext))
    stream = to_nums(clean(keyword)) + p
    return to_text([(p[i] + stream[i]) % 26 for i in range(len(p))])


def autokey_word_decrypt(ciphertext, keyword):
    c = to_nums(clean(ciphertext))
    stream = to_nums(clean(keyword))
    p = []
    for i in range(len(c)):
        val = (c[i] - stream[i]) % 26
        p.append(val)
        stream.append(val)                # extend keystream with recovered letter
    return to_text(p)


def playfair_matrix(key):
    """Build the 5x5 key square: key letters first, then remaining alphabet."""
    key = clean(key).replace("J", "I")
    seen = []
    for ch in key + "ABCDEFGHIKLMNOPQRSTUVWXYZ":   # note: no 'J'
        if ch not in seen:
            seen.append(ch)
    return [seen[i * 5:(i + 1) * 5] for i in range(5)]


def _pf_pos(matrix, ch):
    """Return (row, col) of a letter in the 5x5 matrix."""
    for r in range(5):
        for c in range(5):
            if matrix[r][c] == ch:
                return r, c


def playfair_pairs(text):
    """Split into 2-letter groups; insert 'X' between doubles; pad last with 'X'."""
    text = clean(text).replace("J", "I")
    pairs, i = [], 0
    while i < len(text):
        a = text[i]
        b = text[i + 1] if i + 1 < len(text) else "X"
        if a == b:                       # same letter twice -> separate with X
            pairs.append(a + "X")
            i += 1
        else:
            pairs.append(a + b)
            i += 2
    return pairs


def playfair_encrypt(plaintext, key):
    m = playfair_matrix(key)
    out = ""
    for a, b in playfair_pairs(plaintext):
        r1, c1 = _pf_pos(m, a)
        r2, c2 = _pf_pos(m, b)
        if r1 == r2:                     # same row -> shift RIGHT
            out += m[r1][(c1 + 1) % 5] + m[r2][(c2 + 1) % 5]
        elif c1 == c2:                   # same column -> shift DOWN
            out += m[(r1 + 1) % 5][c1] + m[(r2 + 1) % 5][c2]
        else:                            # rectangle -> swap columns
            out += m[r1][c2] + m[r2][c1]
    return out


def playfair_decrypt(ciphertext, key):
    m = playfair_matrix(key)
    text = clean(ciphertext)
    out = ""
    for i in range(0, len(text), 2):
        a, b = text[i], text[i + 1]
        r1, c1 = _pf_pos(m, a)
        r2, c2 = _pf_pos(m, b)
        if r1 == r2:                     # same row -> shift LEFT
            out += m[r1][(c1 - 1) % 5] + m[r2][(c2 - 1) % 5]
        elif c1 == c2:                   # same column -> shift UP
            out += m[(r1 - 1) % 5][c1] + m[(r2 - 1) % 5][c2]
        else:
            out += m[r1][c2] + m[r2][c1]
    return out


def hill_encrypt(plaintext, key_matrix):
    n = len(key_matrix)
    p = to_nums(clean(plaintext))
    while len(p) % n:                     # pad with 'X' so length divides by n
        p.append(23)
    out = []
    for i in range(0, len(p), n):
        block = p[i:i + n]
        for row in key_matrix:            # row . block  (dot product) mod 26
            out.append(sum(row[j] * block[j] for j in range(n)) % 26)
    return to_text(out)


def matrix_mod_inverse(m, mod=26):
    """Inverse of a 2x2 or 3x3 matrix mod 26 (adjugate / determinant method)."""
    n = len(m)
    if n == 2:
        det = (m[0][0] * m[1][1] - m[0][1] * m[1][0]) % mod
        det_inv = mod_inverse(det, mod)
        if det_inv is None:
            raise ValueError("key matrix not invertible mod 26")
        return [[(m[1][1] * det_inv) % mod, (-m[0][1] * det_inv) % mod],
                [(-m[1][0] * det_inv) % mod, (m[0][0] * det_inv) % mod]]
    # 3x3 via cofactor matrix
    def minor(mat, i, j):
        return [row[:j] + row[j + 1:] for k, row in enumerate(mat) if k != i]
    def det2(x):
        return x[0][0] * x[1][1] - x[0][1] * x[1][0]
    det = sum((-1) ** j * m[0][j] * det2(minor(m, 0, j)) for j in range(3)) % mod
    det_inv = mod_inverse(det, mod)
    if det_inv is None:
        raise ValueError("key matrix not invertible mod 26")
    adj = [[((-1) ** (i + j) * det2(minor(m, j, i))) % mod for j in range(3)]
           for i in range(3)]
    return [[(adj[i][j] * det_inv) % mod for j in range(3)] for i in range(3)]


def hill_decrypt(ciphertext, key_matrix):
    inv = matrix_mod_inverse(key_matrix)  # decryption key = K^-1 mod 26
    return hill_encrypt(ciphertext, inv)  # same maths, inverse key


def keyed_transposition_encrypt(plaintext, perm):
    """perm = tuple like (2,0,1) meaning: out[0]=in[2], out[1]=in[0], out[2]=in[1].
    Text is cut into blocks of len(perm) and each block is permuted."""
    t = clean(plaintext)
    n = len(perm)
    while len(t) % n:
        t += "X"
    out = ""
    for i in range(0, len(t), n):
        block = t[i:i + n]
        out += "".join(block[p] for p in perm)
    return out


def keyed_transposition_decrypt(ciphertext, perm):
    n = len(perm)
    inv = [0] * n
    for i, p in enumerate(perm):          # build the inverse permutation
        inv[p] = i
    out = ""
    for i in range(0, len(ciphertext), n):
        block = ciphertext[i:i + n]
        out += "".join(block[p] for p in inv)
    return out


def rail_fence_encrypt(plaintext, rails):
    """Keyless zig-zag transposition."""
    t = clean(plaintext)
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


def rail_fence_decrypt(ciphertext, rails):
    n = len(ciphertext)
    pattern, r, step = [], 0, 1
    for _ in range(n):                    # first work out which rail each char is on
        pattern.append(r)
        if r == 0:
            step = 1
        elif r == rails - 1:
            step = -1
        r += step
    out = [""] * n
    idx = 0
    for rail in range(rails):
        for i in range(n):
            if pattern[i] == rail:
                out[i] = ciphertext[idx]
                idx += 1
    return "".join(out)


def brute_force_additive(ciphertext, show_all=True):
    """Try all 26 keys. Returns list of (key, plaintext)."""
    results = []
    for k in range(26):
        pt = additive_decrypt(ciphertext, k)
        results.append((k, pt))
        if show_all:
            print(f"key={k:2d} -> {pt}")
    return results


def brute_force_affine(ciphertext, contains=None):
    """Try all valid (a,b) affine keys. If `contains` given, only print hits."""
    valid_a = [a for a in range(1, 26) if mod_inverse(a, 26) is not None]
    hits = []
    for a in valid_a:
        for b in range(26):
            pt = affine_decrypt(ciphertext, a, b)
            if contains is None or contains.upper() in pt:
                hits.append((a, b, pt))
    return hits


def affine_key_from_known_pair(p1, c1, p2, c2):
    """Known-plaintext attack on affine: solve  c = a*p + b  for two pairs.
    p1,c1,p2,c2 are single letters, e.g. ('a','G','b','L')."""
    p1, c1, p2, c2 = (to_nums(clean(x))[0] for x in (p1, c1, p2, c2))
    # c1 - c2 = a*(p1 - p2)  ->  a = (c1-c2) * inv(p1-p2)
    a = ((c1 - c2) * mod_inverse((p1 - p2) % 26, 26)) % 26
    b = (c1 - a * p1) % 26
    return a, b


def shift_key_from_known_pair(plain_char, cipher_char):
    """Known-plaintext attack on shift cipher: k = C - P mod 26."""
    return (to_nums(clean(cipher_char))[0] - to_nums(clean(plain_char))[0]) % 26


def find_transposition_key(plaintext, ciphertext, block_size):
    """Chosen-plaintext attack: recover the permutation used, for a given block size.
    Returns perm tuple, or None if this block size is not consistent."""
    p, c = clean(plaintext), clean(ciphertext)
    if len(p) != len(c) or len(p) % block_size:
        return None
    perm = []
    for j in range(block_size):           # which input position produced output j?
        found = None
        for i in range(block_size):
            if all(c[b + j] == p[b + i]
                   for b in range(0, len(p), block_size)):
                found = i
                break
        if found is None:
            return None
        perm.append(found)
    return tuple(perm)


# ==========================================================================
### FROM c02_symmetric_des_aes.py
# ==========================================================================

def make_key(key, size):
    """Turn whatever the question gives you into EXACTLY `size` bytes.

    Accepts: bytes, a hex string ("A1B2C3D4"), or plain text ("mysecret").
    Rule used: if the string looks like hex AND decodes to the right length,
    treat it as hex; otherwise treat it as ASCII. Then pad/truncate."""
    if isinstance(key, bytes):
        k = key
    else:
        s = key.strip()
        try:
            h = bytes.fromhex(s)          # "A1B2C3D4" -> b'\xa1\xb2\xc3\xd4'
            k = h if len(h) == size else s.encode()
        except ValueError:
            k = s.encode()
    if len(k) < size:
        k = k + b"\0" * (size - len(k))   # zero-pad if short
    return k[:size]                       # truncate if long


def des_encrypt(plaintext, key, mode="ECB", iv=None):
    k = make_key(key, 8)
    data = plaintext.encode() if isinstance(plaintext, str) else plaintext
    if mode == "ECB":
        c = DES.new(k, DES.MODE_ECB)
        return c.encrypt(pad(data, 8))
    if mode == "CBC":
        iv = make_key(iv, 8) if iv else get_random_bytes(8)
        c = DES.new(k, DES.MODE_CBC, iv)
        return iv + c.encrypt(pad(data, 8))      # IV prepended to ciphertext
    if mode == "CFB":
        iv = make_key(iv, 8) if iv else get_random_bytes(8)
        c = DES.new(k, DES.MODE_CFB, iv)
        return iv + c.encrypt(data)              # stream mode: no padding
    raise ValueError("mode must be ECB / CBC / CFB")


def des_decrypt(ciphertext, key, mode="ECB"):
    k = make_key(key, 8)
    if mode == "ECB":
        c = DES.new(k, DES.MODE_ECB)
        return unpad(c.decrypt(ciphertext), 8)
    if mode == "CBC":
        iv, body = ciphertext[:8], ciphertext[8:]   # split IV back off
        c = DES.new(k, DES.MODE_CBC, iv)
        return unpad(c.decrypt(body), 8)
    if mode == "CFB":
        iv, body = ciphertext[:8], ciphertext[8:]
        c = DES.new(k, DES.MODE_CFB, iv)
        return c.decrypt(body)
    raise ValueError("mode must be ECB / CBC / CFB")


def make_des3_key(key):
    """Build a valid 24-byte 3DES key.

    TRAP: 3DES key = K1|K2|K3. pycryptodome REFUSES a key where K1==K2 or
    K2==K3, because then 3DES collapses into plain DES. The lab manual's key
    "1234567890ABCDEF..." repeats every 8 bytes, so it is exactly that case.
    Fix: flip one bit in K2 so the key is a genuine 3-key Triple DES key."""
    k = make_key(key, 24)
    k1, k2, k3 = k[:8], k[8:16], k[16:]
    if k1 == k2 or k2 == k3:
        # 0x02, not 0x01: bit 0 is the DES parity bit and would be undone below
        k2 = bytes([k2[0] ^ 0x02]) + k2[1:]
        k = k1 + k2 + k3
    return DES3.adjust_key_parity(k)          # library wants odd parity bytes


def des3_encrypt(plaintext, key):
    k = make_des3_key(key)
    data = plaintext.encode() if isinstance(plaintext, str) else plaintext
    c = DES3.new(k, DES3.MODE_ECB)
    return c.encrypt(pad(data, 8))


def des3_decrypt(ciphertext, key):
    k = make_des3_key(key)
    c = DES3.new(k, DES3.MODE_ECB)
    return unpad(c.decrypt(ciphertext), 8)


def aes_encrypt(plaintext, key, bits=128, mode="ECB", iv=None, nonce=None):
    k = make_key(key, bits // 8)
    data = plaintext.encode() if isinstance(plaintext, str) else plaintext
    if mode == "ECB":
        return AES.new(k, AES.MODE_ECB).encrypt(pad(data, 16))
    if mode == "CBC":
        iv = make_key(iv, 16) if iv else get_random_bytes(16)
        return iv + AES.new(k, AES.MODE_CBC, iv).encrypt(pad(data, 16))
    if mode == "CTR":
        n = make_key(nonce, 8) if nonce else get_random_bytes(8)
        c = AES.new(k, AES.MODE_CTR, nonce=n)
        return n + c.encrypt(data)                # counter mode: no padding
    if mode == "CFB":
        iv = make_key(iv, 16) if iv else get_random_bytes(16)
        return iv + AES.new(k, AES.MODE_CFB, iv).encrypt(data)
    if mode == "OFB":
        iv = make_key(iv, 16) if iv else get_random_bytes(16)
        return iv + AES.new(k, AES.MODE_OFB, iv).encrypt(data)
    raise ValueError("bad mode")


def aes_decrypt(ciphertext, key, bits=128, mode="ECB"):
    k = make_key(key, bits // 8)
    if mode == "ECB":
        return unpad(AES.new(k, AES.MODE_ECB).decrypt(ciphertext), 16)
    if mode == "CBC":
        iv, body = ciphertext[:16], ciphertext[16:]
        return unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(body), 16)
    if mode == "CTR":
        n, body = ciphertext[:8], ciphertext[8:]
        return AES.new(k, AES.MODE_CTR, nonce=n).decrypt(body)
    if mode == "CFB":
        iv, body = ciphertext[:16], ciphertext[16:]
        return AES.new(k, AES.MODE_CFB, iv).decrypt(body)
    if mode == "OFB":
        iv, body = ciphertext[:16], ciphertext[16:]
        return AES.new(k, AES.MODE_OFB, iv).decrypt(body)
    raise ValueError("bad mode")


SBOX = [
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


RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d]


def aes_key_expansion(key_bytes):
    """Return the list of 4-byte words of the expanded key.
    Nk = key words (4/6/8), Nr = rounds (10/12/14), total words = 4*(Nr+1)."""
    nk = len(key_bytes) // 4
    nr = {4: 10, 6: 12, 8: 14}[nk]
    w = [list(key_bytes[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        temp = list(w[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]                    # RotWord
            temp = [SBOX[b] for b in temp]                # SubWord
            temp[0] ^= RCON[i // nk - 1]                  # XOR Rcon
        elif nk > 6 and i % nk == 4:
            temp = [SBOX[b] for b in temp]                # extra SubWord for AES-256
        w.append([w[i - nk][j] ^ temp[j] for j in range(4)])
    return w, nr


def print_round_keys(key_bytes):
    """Pretty-print each round key - use this when the question says 'show steps'."""
    w, nr = aes_key_expansion(key_bytes)
    print(f"Key length {len(key_bytes)*8} bits -> {nr} rounds, {len(w)} words")
    for r in range(nr + 1):
        rk = b"".join(bytes(word) for word in w[4 * r:4 * r + 4])
        print(f"  Round key {r:2d}: {rk.hex().upper()}")
    return w


def time_it(func, *args, repeat=100, **kwargs):
    """Run func `repeat` times, return (result, average seconds)."""
    import time
    start = time.perf_counter()
    for _ in range(repeat):
        result = func(*args, **kwargs)
    return result, (time.perf_counter() - start) / repeat


def bar(value, biggest, width=40):
    """Tiny text bar chart - avoids needing matplotlib in the exam."""
    n = int(width * value / biggest) if biggest else 0
    return "#" * max(n, 1)


# ==========================================================================
### FROM c03_rsa.py
# ==========================================================================

def rsa_generate(bits=2048):
    """Generate an RSA key pair. Returns the key object.
    key.publickey() -> public part ; key itself holds the private part."""
    return RSA.generate(bits)


def rsa_encrypt(message, public_key):
    """Encrypt with OAEP padding. NOTE: max message size is about
    (key_bytes - 42). For 2048-bit keys that is ~214 bytes."""
    data = message.encode() if isinstance(message, str) else message
    return PKCS1_OAEP.new(public_key).encrypt(data)


def rsa_decrypt(ciphertext, private_key):
    return PKCS1_OAEP.new(private_key).decrypt(ciphertext)


def rsa_sign(message, private_key):
    """Digital signature = RSA over the SHA-256 hash of the message."""
    data = message.encode() if isinstance(message, str) else message
    h = SHA256.new(data)
    return pkcs1_15.new(private_key).sign(h)


def rsa_verify(message, signature, public_key):
    """Returns True/False instead of raising - easier to use in a menu."""
    data = message.encode() if isinstance(message, str) else message
    h = SHA256.new(data)
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


def rsa_sign_pss(message, private_key):
    """PSS is the modern (probabilistic) signature padding. Same idea."""
    data = message.encode() if isinstance(message, str) else message
    return pss.new(private_key).sign(SHA256.new(data))


def rsa_verify_pss(message, signature, public_key):
    data = message.encode() if isinstance(message, str) else message
    try:
        pss.new(public_key).verify(SHA256.new(data), signature)
        return True
    except (ValueError, TypeError):
        return False


def rsa_encrypt_large(data, public_key):
    """Returns (encrypted_aes_key, nonce, tag, ciphertext)."""
    data = data.encode() if isinstance(data, str) else data
    session_key = get_random_bytes(16)                   # random AES-128 key
    cipher = AES.new(session_key, AES.MODE_EAX)          # EAX = encrypt + auth
    ct, tag = cipher.encrypt_and_digest(data)
    enc_key = PKCS1_OAEP.new(public_key).encrypt(session_key)
    return enc_key, cipher.nonce, tag, ct


def rsa_decrypt_large(enc_key, nonce, tag, ct, private_key):
    session_key = PKCS1_OAEP.new(private_key).decrypt(enc_key)
    cipher = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)


def save_keys(key, priv_file="private.pem", pub_file="public.pem"):
    """Write keys to PEM files (questions often say 'store keys securely')."""
    with open(priv_file, "wb") as f:
        f.write(key.export_key())
    with open(pub_file, "wb") as f:
        f.write(key.publickey().export_key())


def load_key(path):
    with open(path, "rb") as f:
        return RSA.import_key(f.read())


def modinv(a, m):
    """Modular inverse using extended Euclid - works for huge numbers."""
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError("no modular inverse")
    return x % m


def rsa_keygen_manual(p, q, e=65537):
    """Build (n,e) and (n,d) from two primes - shows the actual RSA steps."""
    n = p * q
    phi = (p - 1) * (q - 1)
    if egcd(e, phi)[0] != 1:
        raise ValueError("e is not coprime with phi(n)")
    d = modinv(e, phi)
    return (n, e), (n, d)


def rsa_encrypt_manual(message, n, e):
    """Encrypt each CHARACTER separately: c = ord(ch)^e mod n.
    Use this when n is small (like 323) - a whole message will not fit."""
    return [pow(ord(ch), e, n) for ch in message]


def rsa_decrypt_manual(cipher_list, n, d):
    return "".join(chr(pow(c, d, n)) for c in cipher_list)


def rsa_encrypt_int(m, n, e):
    """Encrypt one integer (m must be < n)."""
    return pow(m, e, n)


def rsa_decrypt_int(c, n, d):
    return pow(c, d, n)


def bytes_to_int(b):
    return int.from_bytes(b, "big")


def int_to_bytes(i):
    return i.to_bytes((i.bit_length() + 7) // 8 or 1, "big")


def fermat_factor(n, max_steps=1_000_000):
    """If p and q are close, n = a^2 - b^2 = (a-b)(a+b) is found fast."""
    import math
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(max_steps):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:                      # perfect square -> factors found
            return a - b, a + b
        a += 1
    return None


def recover_private_key(n, e, p, q):
    """Once p,q are known the private exponent falls out immediately."""
    phi = (p - 1) * (q - 1)
    return modinv(e, phi)


def is_prime(num, k=20):
    """Miller-Rabin primality test - needed to generate your own primes."""
    if num < 2:
        return False
    for sp in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if num % sp == 0:
            return num == sp
    d, r = num - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(k):
        a = random.randrange(2, num - 1)
        x = pow(a, d, num)
        if x in (1, num - 1):
            continue
        for _ in range(r - 1):
            x = x * x % num
            if x == num - 1:
                break
        else:
            return False
    return True


def gen_prime(bits):
    """Random prime of the requested bit length."""
    while True:
        cand = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_prime(cand):
            return cand


# ==========================================================================
### FROM c04_elgamal.py
# ==========================================================================

def gen_safe_prime(bits):
    """p = 2q+1 with q prime. Then g=2 is (almost always) a good generator."""
    while True:
        q = random.getrandbits(bits - 1) | (1 << (bits - 2)) | 1
        if is_prime(q):
            p = 2 * q + 1
            if is_prime(p):
                return p, q


def elgamal_keygen(bits=256):
    """Returns (public_key, private_key) = ((p, g, y), x).
    Keep bits small (256) in an exam - 2048-bit safe primes take minutes."""
    p, q = gen_safe_prime(bits)
    g = 2
    x = random.randrange(2, p - 2)          # private key
    y = pow(g, x, p)                        # public key component
    return (p, g, y), x


def elgamal_encrypt_int(m, pub):
    """Encrypt one integer m (must satisfy m < p)."""
    p, g, y = pub
    k = random.randrange(2, p - 2)          # fresh random k for EVERY message
    c1 = pow(g, k, p)
    c2 = (m * pow(y, k, p)) % p
    return (c1, c2)


def elgamal_decrypt_int(ct, priv, p):
    c1, c2 = ct
    s = pow(c1, priv, p)                    # shared secret = c1^x
    return (c2 * modinv(s, p)) % p


def elgamal_encrypt(message, pub):
    """Encrypt a STRING. If the whole message fits in one integer (< p) we send
    one block; otherwise we fall back to one block per character."""
    p, g, y = pub
    data = message.encode() if isinstance(message, str) else message
    m = int.from_bytes(data, "big")
    if m < p:
        return [elgamal_encrypt_int(m, pub)], "whole"
    return [elgamal_encrypt_int(b, pub) for b in data], "bytes"


def elgamal_decrypt(cipher, priv, pub, mode):
    p = pub[0]
    if mode == "whole":
        m = elgamal_decrypt_int(cipher[0], priv, p)
        return m.to_bytes((m.bit_length() + 7) // 8 or 1, "big").decode()
    return bytes(elgamal_decrypt_int(c, priv, p) for c in cipher).decode()


def elgamal_encrypt_chars(message, pub):
    """Per-character version - use when p is TINY (e.g. p = 7919 in the manual)."""
    return [elgamal_encrypt_int(ord(ch), pub) for ch in message]


def elgamal_decrypt_chars(cipher, priv, p):
    return "".join(chr(elgamal_decrypt_int(c, priv, p)) for c in cipher)


def elgamal_sign(message, priv, pub):
    """Signature = (r, s). Hash is reduced mod (p-1)."""
    p, g, y = pub
    data = message.encode() if isinstance(message, str) else message
    h = int(hashlib.sha256(data).hexdigest(), 16) % (p - 1)
    while True:
        k = random.randrange(2, p - 2)
        if egcd(k, p - 1)[0] == 1:          # k must be invertible mod p-1
            break
    r = pow(g, k, p)
    s = ((h - priv * r) * modinv(k, p - 1)) % (p - 1)
    return (r, s)


def elgamal_verify(message, signature, pub):
    p, g, y = pub
    r, s = signature
    if not (0 < r < p):
        return False
    data = message.encode() if isinstance(message, str) else message
    h = int(hashlib.sha256(data).hexdigest(), 16) % (p - 1)
    left = pow(g, h, p)                      # g^h
    right = (pow(y, r, p) * pow(r, s, p)) % p  # y^r * r^s
    return left == right


def schnorr_keygen(bits=256):
    p, q = gen_safe_prime(bits)
    g = pow(2, (p - 1) // q, p)              # g has order q
    x = random.randrange(1, q)
    y = pow(g, x, p)
    return (p, q, g, y), x


def schnorr_sign(message, priv, pub):
    p, q, g, y = pub
    data = message.encode() if isinstance(message, str) else message
    k = random.randrange(1, q)
    r = pow(g, k, p)
    e = int(hashlib.sha256(str(r).encode() + data).hexdigest(), 16) % q
    s = (k + priv * e) % q
    return (e, s)


def schnorr_verify(message, signature, pub):
    p, q, g, y = pub
    e, s = signature
    data = message.encode() if isinstance(message, str) else message
    rv = (pow(g, s, p) * pow(y, q - e % q, p)) % p   # g^s * y^(-e)
    ev = int(hashlib.sha256(str(rv).encode() + data).hexdigest(), 16) % q
    return ev == e


# ==========================================================================
### FROM c05_ecc.py
# ==========================================================================

def ecc_generate(curve="P-256"):
    """Private key object; .public_key() gives the public half.
    Curves you may be asked for: P-256 (secp256r1), P-384, P-521."""
    return ECC.generate(curve=curve)


def ecdh_shared_secret(my_private, their_public):
    """Shared point = my_private_scalar * their_public_point.
    Both sides get the SAME x coordinate -> hash it to make an AES key."""
    point = their_public.pointQ * my_private.d
    # size_in_bytes() adapts to the curve (32 for P-256, 66 for P-521)
    x_bytes = int(point.x).to_bytes(point.size_in_bytes(), "big")
    return hashlib.sha256(x_bytes).digest()       # 32-byte symmetric key


def ecc_encrypt(message, recipient_public):
    """Returns (ephemeral_public_pem, nonce, tag, ciphertext)."""
    data = message.encode() if isinstance(message, str) else message
    eph = ECC.generate(curve=recipient_public.curve)      # one-time key pair
    key = ecdh_shared_secret(eph, recipient_public)       # shared AES key
    cipher = AES.new(key, AES.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(data)
    return eph.public_key().export_key(format="PEM"), cipher.nonce, tag, ct


def ecc_decrypt(eph_pub_pem, nonce, tag, ct, my_private):
    eph_pub = ECC.import_key(eph_pub_pem)
    key = ecdh_shared_secret(my_private, eph_pub)         # same shared secret
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)


def ecc_sign(message, private_key):
    data = message.encode() if isinstance(message, str) else message
    h = SHA256.new(data)
    return DSS.new(private_key, "fips-186-3").sign(h)


def ecc_verify(message, signature, public_key):
    data = message.encode() if isinstance(message, str) else message
    h = SHA256.new(data)
    try:
        DSS.new(public_key, "fips-186-3").verify(h, signature)
        return True
    except ValueError:
        return False


def point_add(P, Q, a, p):
    """Add two points on the curve. None represents the point at infinity."""
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None                                   # P + (-P) = infinity
    if P == Q:
        lam = (3 * x1 * x1 + a) * pow(2 * y1, -1, p) % p   # tangent slope
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, p) % p          # chord slope
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)


def point_multiply(k, P, a, p):
    """Scalar multiply k*P by double-and-add (this IS the ECC 'hard problem')."""
    result, addend = None, P
    while k:
        if k & 1:
            result = point_add(result, addend, a, p)
        addend = point_add(addend, addend, a, p)
        k >>= 1
    return result


DEMO_CURVE = dict(p=97, a=2, b=3, G=(3, 6), n=5)


# ==========================================================================
### FROM c06_rabin.py
# ==========================================================================

def gen_blum_prime(bits):
    """A 'Blum prime': prime AND congruent to 3 mod 4."""
    while True:
        cand = random.getrandbits(bits) | (1 << (bits - 1)) | 3
        if cand % 4 == 3 and is_prime(cand):
            return cand


def rabin_keygen(bits=1024):
    """bits = size of n. Each prime gets bits/2. Returns (n, (p, q))."""
    half = bits // 2
    p = gen_blum_prime(half)
    q = gen_blum_prime(half)
    while q == p:
        q = gen_blum_prime(half)
    return p * q, (p, q)


MARKER = b"##"        # redundancy so we can pick the correct root


def rabin_encrypt(message, n):
    data = message.encode() if isinstance(message, str) else message
    m = int.from_bytes(data + MARKER, "big")
    if m >= n:
        raise ValueError("message too long for this key size")
    return pow(m, 2, n)                     # c = m^2 mod n


def rabin_decrypt(c, p, q):
    """Return the one root that carries the marker (or all four if none does)."""
    n = p * q
    mp = pow(c, (p + 1) // 4, p)            # square root mod p
    mq = pow(c, (q + 1) // 4, q)            # square root mod q
    _, yp, yq = egcd(p, q)                  # yp*p + yq*q = 1
    r1 = (yp * p * mq + yq * q * mp) % n
    r2 = n - r1
    r3 = (yp * p * mq - yq * q * mp) % n
    r4 = n - r3
    for r in (r1, r2, r3, r4):
        b = r.to_bytes((r.bit_length() + 7) // 8 or 1, "big")
        if b.endswith(MARKER):
            return b[:-len(MARKER)]         # strip marker -> original message
    return [r1, r2, r3, r4]                 # marker not found: return all roots


def rabin_roots(c, p, q):
    """All four square roots, for questions that ask you to SHOW them."""
    n = p * q
    mp = pow(c, (p + 1) // 4, p)
    mq = pow(c, (q + 1) // 4, q)
    _, yp, yq = egcd(p, q)
    r1 = (yp * p * mq + yq * q * mp) % n
    r3 = (yp * p * mq - yq * q * mp) % n
    return [r1, n - r1, r3, n - r3]


def rabin_sign(message, p, q):
    """Sign by finding a square root of H(m) - only the key owner can."""
    n = p * q
    data = message.encode() if isinstance(message, str) else message
    for pad in range(1 << 16):              # nudge the hash until it is a QR
        h = int(hashlib.sha256(data + str(pad).encode()).hexdigest(), 16) % n
        if pow(h, (p - 1) // 2, p) == 1 and pow(h, (q - 1) // 2, q) == 1:
            mp = pow(h, (p + 1) // 4, p)
            mq = pow(h, (q + 1) // 4, q)
            _, yp, yq = egcd(p, q)
            s = (yp * p * mq + yq * q * mp) % n
            return s, pad
    raise RuntimeError("could not sign")


def rabin_verify(message, signature, n):
    s, pad = signature
    data = message.encode() if isinstance(message, str) else message
    h = int(hashlib.sha256(data + str(pad).encode()).hexdigest(), 16) % n
    return pow(s, 2, n) == h                # s^2 mod n must equal the hash


# ==========================================================================
### FROM c07_diffie_hellman.py
# ==========================================================================

P_2048 = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)


G_2048 = 2


class DHParty:
    """One peer in a Diffie-Hellman exchange."""

    def __init__(self, name, p=P_2048, g=G_2048):
        self.name = name
        self.p, self.g = p, g
        self.private = random.randrange(2, p - 2)     # secret exponent
        self.public = pow(g, self.private, p)         # g^private mod p
        self.shared = None

    def compute_shared(self, other_public):
        """s = other_public ^ my_private mod p"""
        self.shared = pow(other_public, self.private, self.p)
        return self.shared

    def session_key(self):
        """Hash the shared number down to a 32-byte AES key.
        NEVER use the raw DH number as an AES key - always hash it."""
        b = self.shared.to_bytes((self.shared.bit_length() + 7) // 8, "big")
        return hashlib.sha256(b).digest()


def dh_exchange(p=P_2048, g=G_2048, verbose=True):
    """Full exchange between two peers; returns (alice, bob, timings)."""
    t0 = time.perf_counter()
    alice = DHParty("Alice", p, g)
    bob = DHParty("Bob", p, g)
    t_keygen = time.perf_counter() - t0

    t0 = time.perf_counter()
    alice.compute_shared(bob.public)          # exchange public values
    bob.compute_shared(alice.public)
    t_exchange = time.perf_counter() - t0

    if verbose:
        print(f"Alice public : {str(alice.public)[:40]}...")
        print(f"Bob   public : {str(bob.public)[:40]}...")
        print(f"secrets match: {alice.shared == bob.shared}")
        print(f"key gen  time: {t_keygen*1000:.2f} ms")
        print(f"exchange time: {t_exchange*1000:.2f} ms")
    return alice, bob, (t_keygen, t_exchange)


def dh_small_demo(p=23, g=5, a=6, b=15):
    """Textbook numbers you can write out by hand in a viva."""
    A, B = pow(g, a, p), pow(g, b, p)
    s1, s2 = pow(B, a, p), pow(A, b, p)
    print(f"p={p} g={g} | a={a} A={A} | b={b} B={B} | shared={s1}=={s2}")
    return s1


def dh_secure_message(sender, receiver, message):
    """sender/receiver are DHParty objects that already ran compute_shared."""
    from Crypto.Cipher import AES
    key = sender.session_key()
    c = AES.new(key, AES.MODE_EAX)
    ct, tag = c.encrypt_and_digest(message.encode())
    # receiver side
    d = AES.new(receiver.session_key(), AES.MODE_EAX, nonce=c.nonce)
    return d.decrypt_and_verify(ct, tag).decode()


# ==========================================================================
### FROM c08_hashing.py
# ==========================================================================

def sha256_hex(data):
    """The one you will use 90% of the time."""
    data = data.encode() if isinstance(data, str) else data
    return hashlib.sha256(data).hexdigest()


def hash_with(data, algo="sha256"):
    """algo: 'md5' | 'sha1' | 'sha256' | 'sha512'"""
    data = data.encode() if isinstance(data, str) else data
    return hashlib.new(algo, data).hexdigest()


def hash_file(path, algo="sha256", chunk=8192):
    """Hash a file without loading it all into memory."""
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        while True:
            block = f.read(chunk)
            if not block:
                break
            h.update(block)                 # feed the hash in pieces
    return h.hexdigest()


def verify_integrity(data, expected_hash, algo="sha256"):
    """Recompute and compare - this is 'integrity checking'."""
    return hash_with(data, algo) == expected_hash


def custom_hash(text):
    h = 5381                                      # magic starting value
    for ch in text:
        h = (h * 33) + ord(ch)                    # multiply by 33, add char
        h ^= (h >> 15)                            # mix high bits into low
        h = (h << 5) ^ h                          # more mixing
        h &= 0xFFFFFFFF                           # keep it 32-bit
    return h & 0xFFFFFFFF


def custom_hash_verbose(text):
    """Same thing but prints each step - good for the write-up."""
    h = 5381
    print(f"initial       : {h}")
    for ch in text:
        h = (h * 33 + ord(ch)) & 0xFFFFFFFF
        h ^= (h >> 15)
        h = ((h << 5) ^ h) & 0xFFFFFFFF
        print(f"after '{ch}'    : {h:10d}  (0x{h:08X})")
    return h


def hmac_sha256(key, message):
    import hmac
    key = key.encode() if isinstance(key, str) else key
    msg = message.encode() if isinstance(message, str) else message
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def hmac_verify(key, message, tag):
    import hmac
    return hmac.compare_digest(hmac_sha256(key, message), tag)  # timing-safe


def random_strings(count=100, min_len=5, max_len=20):
    """Dataset generator for the experiment."""
    pool = string.ascii_letters + string.digits
    return ["".join(random.choices(pool, k=random.randint(min_len, max_len)))
            for _ in range(count)]


def time_hash(algo, dataset):
    """Total seconds to hash the whole dataset with one algorithm."""
    start = time.perf_counter()
    for s in dataset:
        hashlib.new(algo, s.encode()).hexdigest()
    return time.perf_counter() - start


def find_collisions(dataset, algo="sha256", truncate_bits=None):
    """Full hashes almost never collide. Pass truncate_bits (e.g. 24) to
    shorten the digest so the birthday effect becomes visible."""
    seen, collisions = {}, []
    for s in dataset:
        d = hashlib.new(algo, s.encode()).hexdigest()
        if truncate_bits:
            d = d[:truncate_bits // 4]            # 4 bits per hex character
        if d in seen and seen[d] != s:
            collisions.append((seen[d], s, d))
        seen[d] = s
    return collisions


def avalanche_demo(text="hello"):
    """Show that a 1-character change completely changes the digest."""
    a = sha256_hex(text)
    b = sha256_hex(text[:-1] + chr(ord(text[-1]) ^ 1))
    diff = sum(bin(int(x, 16) ^ int(y, 16)).count("1") for x, y in zip(a, b))
    print(f"{text} -> {a}")
    print(f"changed -> {b}")
    print(f"bits different: {diff}/256")


# ==========================================================================
### FROM c09_digital_signature.py
# ==========================================================================

def rsa_keys(bits=2048):
    k = RSA.generate(bits)
    return k, k.publickey()


def sign_rsa(message, private_key):
    data = message.encode() if isinstance(message, str) else message
    return pkcs1_15.new(private_key).sign(SHA256.new(data))


def verify_rsa(message, signature, public_key):
    data = message.encode() if isinstance(message, str) else message
    try:
        pkcs1_15.new(public_key).verify(SHA256.new(data), signature)
        return True
    except (ValueError, TypeError):
        return False


def dsa_keys(bits=2048):
    k = DSA.generate(bits)
    return k, k.publickey()


def sign_dsa(message, private_key):
    data = message.encode() if isinstance(message, str) else message
    return DSS.new(private_key, "fips-186-3").sign(SHA256.new(data))


def verify_dsa(message, signature, public_key):
    data = message.encode() if isinstance(message, str) else message
    try:
        DSS.new(public_key, "fips-186-3").verify(SHA256.new(data), signature)
        return True
    except ValueError:
        return False


def ecdsa_keys(curve="P-256"):
    k = ECC.generate(curve=curve)
    return k, k.public_key()


def sign_ecdsa(message, private_key):
    data = message.encode() if isinstance(message, str) else message
    return DSS.new(private_key, "fips-186-3").sign(SHA256.new(data))


def verify_ecdsa(message, signature, public_key):
    data = message.encode() if isinstance(message, str) else message
    try:
        DSS.new(public_key, "fips-186-3").verify(SHA256.new(data), signature)
        return True
    except ValueError:
        return False


def sign_rsa_manual(message, n, d):
    data = message.encode() if isinstance(message, str) else message
    h = int(hashlib.sha256(data).hexdigest(), 16) % n
    return pow(h, d, n)


def verify_rsa_manual(message, signature, n, e):
    data = message.encode() if isinstance(message, str) else message
    h = int(hashlib.sha256(data).hexdigest(), 16) % n
    return pow(signature, e, n) == h


def sign_hex_blob(hex_string, n, d):
    """Lab 6 Part 1 style: the 'signature' in the manual is just a big number
    written as 0x.. bytes. This converts hex -> int -> RSA operation."""
    m = int(hex_string.replace("0x", "").replace(" ", ""), 16)
    return pow(m % n, d, n)


def recover_signed_value(signature_int, n, e):
    """Apply the public key to a signature to see what was signed.
    That is literally what the online RSA tool in Lab 6 does."""
    v = pow(signature_int, e, n)
    b = v.to_bytes((v.bit_length() + 7) // 8 or 1, "big")
    return v, b


def secure_send(message, sender_private, receiver_public):
    """Returns a dict you can store in a file / database."""
    from Crypto.Cipher import PKCS1_OAEP, AES
    from Crypto.Random import get_random_bytes
    data = message.encode()
    digest = hashlib.sha256(data).hexdigest()              # INTEGRITY
    signature = sign_rsa(data, sender_private)             # AUTHENTICITY
    session = get_random_bytes(16)
    c = AES.new(session, AES.MODE_EAX)
    ct, tag = c.encrypt_and_digest(data)                   # CONFIDENTIALITY
    enc_key = PKCS1_OAEP.new(receiver_public).encrypt(session)
    return dict(enc_key=enc_key, nonce=c.nonce, tag=tag, ct=ct,
                hash=digest, signature=signature)


def secure_receive(pkt, receiver_private, sender_public):
    from Crypto.Cipher import PKCS1_OAEP, AES
    session = PKCS1_OAEP.new(receiver_private).decrypt(pkt["enc_key"])
    c = AES.new(session, AES.MODE_EAX, nonce=pkt["nonce"])
    data = c.decrypt_and_verify(pkt["ct"], pkt["tag"])
    ok_hash = hashlib.sha256(data).hexdigest() == pkt["hash"]
    ok_sig = verify_rsa(data, pkt["signature"], sender_public)
    return data.decode(), ok_hash, ok_sig


# ==========================================================================
### FROM c10_key_management.py
# ==========================================================================

def derive_master_key(password, salt):
    """PBKDF2: slow on purpose, so guessing the password is expensive."""
    return PBKDF2(password, salt, dkLen=32, count=100_000)


def encrypt_blob(data, password):
    """Returns salt + nonce + tag + ciphertext, all in one bytes object."""
    salt = get_random_bytes(16)
    key = derive_master_key(password, salt)
    c = AES.new(key, AES.MODE_GCM)
    ct, tag = c.encrypt_and_digest(data)
    return salt + c.nonce + tag + ct


def decrypt_blob(blob, password):
    salt, nonce, tag, ct = blob[:16], blob[16:32], blob[32:48], blob[48:]
    key = derive_master_key(password, salt)
    return AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)


class AuditLog:
    """Append-only log. Every KMS question asks for 'auditing and logging'."""

    def __init__(self, path="audit.log"):
        self.path = path
        self.entries = []

    def record(self, actor, action, detail=""):
        line = f"{datetime.now().isoformat(timespec='seconds')} | {actor} | {action} | {detail}"
        self.entries.append(line)
        with open(self.path, "a") as f:
            f.write(line + "\n")
        return line

    def show(self, n=20):
        for line in self.entries[-n:]:
            print("  " + line)


class KeyManagementService:

    def __init__(self, master_password="master-secret", key_bits=2048,
                 lifetime_days=365, store_dir="kms_store"):
        self.master_password = master_password
        self.key_bits = key_bits
        self.lifetime = timedelta(days=lifetime_days)
        self.store_dir = store_dir
        os.makedirs(store_dir, exist_ok=True)
        self.registry = {}          # entity -> metadata dict
        self.log = AuditLog(os.path.join(store_dir, "audit.log"))

    # --- 1. GENERATION ----------------------------------------------------
    def generate(self, entity):
        key = RSA.generate(self.key_bits)
        priv_pem = key.export_key()
        pub_pem = key.publickey().export_key()
        # store the PRIVATE key encrypted; the public key in clear
        with open(self._path(entity, "priv.enc"), "wb") as f:
            f.write(encrypt_blob(priv_pem, self.master_password))
        with open(self._path(entity, "pub.pem"), "wb") as f:
            f.write(pub_pem)
        self.registry[entity] = dict(
            created=datetime.now().isoformat(timespec="seconds"),
            expires=(datetime.now() + self.lifetime).isoformat(timespec="seconds"),
            revoked=False,
            fingerprint=hashlib.sha256(pub_pem).hexdigest()[:16])
        self.log.record(entity, "KEY_GENERATED", f"{self.key_bits}-bit RSA")
        return pub_pem

    # --- 2. DISTRIBUTION --------------------------------------------------
    def get_public_key(self, entity):
        """Anyone may fetch a public key - unless it has been revoked."""
        self._check_active(entity)
        self.log.record(entity, "PUBLIC_KEY_ISSUED")
        with open(self._path(entity, "pub.pem"), "rb") as f:
            return RSA.import_key(f.read())

    def get_private_key(self, entity, password):
        """Only with the master password. Decrypts the stored blob."""
        self._check_active(entity)
        with open(self._path(entity, "priv.enc"), "rb") as f:
            pem = decrypt_blob(f.read(), password)
        self.log.record(entity, "PRIVATE_KEY_ISSUED")
        return RSA.import_key(pem)

    # --- 3. REVOCATION ----------------------------------------------------
    def revoke(self, entity, reason="unspecified"):
        self.registry[entity]["revoked"] = True
        self.registry[entity]["revoked_at"] = datetime.now().isoformat(timespec="seconds")
        self.log.record(entity, "KEY_REVOKED", reason)

    # --- 4. RENEWAL -------------------------------------------------------
    def renew(self, entity):
        """Throw the old pair away and issue a new one."""
        self.log.record(entity, "KEY_RENEWAL_STARTED")
        self.generate(entity)
        self.registry[entity]["revoked"] = False
        return self.registry[entity]

    def renew_expired(self):
        """Call this periodically - renews everything past its expiry date."""
        now = datetime.now()
        renewed = []
        for e, meta in list(self.registry.items()):
            if datetime.fromisoformat(meta["expires"]) <= now:
                self.renew(e)
                renewed.append(e)
        return renewed

    # --- helpers ----------------------------------------------------------
    def _path(self, entity, suffix):
        return os.path.join(self.store_dir, f"{entity}_{suffix}")

    def _check_active(self, entity):
        if entity not in self.registry:
            raise KeyError(f"{entity} has no keys")
        if self.registry[entity]["revoked"]:
            raise PermissionError(f"{entity}'s key is REVOKED")

    def status(self):
        print(f"{'entity':<12}{'created':<21}{'expires':<21}{'revoked'}")
        for e, m in self.registry.items():
            print(f"{e:<12}{m['created']:<21}{m['expires']:<21}{m['revoked']}")


# ==========================================================================
### FROM c11_access_control.py
# ==========================================================================

ROLE_PERMISSIONS = {
    "student": {"encrypt", "sign", "upload", "view_own"},
    "faculty": {"decrypt", "verify", "hash", "view_all"},
    "hod":     {"view_hash", "verify"},
    "admin":   {"encrypt", "decrypt", "sign", "verify", "hash",
                "upload", "view_all", "view_hash", "manage_users"},
}


class User:
    """One account. Password is stored as a salted SHA-256 hash, never plain."""

    def __init__(self, username, password, role):
        self.username = username
        self.role = role
        self.salt = os.urandom(16)
        self.pw_hash = self._hash(password)
        self.created = datetime.now()

    def _hash(self, password):
        return hashlib.sha256(self.salt + password.encode()).hexdigest()

    def check_password(self, password):
        return self._hash(password) == self.pw_hash

    def permissions(self):
        return ROLE_PERMISSIONS.get(self.role, set())

    def can(self, action):
        return action in self.permissions()


class AccessControl:
    """Small in-memory user directory + login + permission checks."""

    def __init__(self):
        self.users = {}
        self.current = None                      # who is logged in

    def add_user(self, username, password, role):
        if role not in ROLE_PERMISSIONS:
            raise ValueError(f"unknown role {role}")
        self.users[username] = User(username, password, role)
        return self.users[username]

    def login(self, username, password):
        u = self.users.get(username)
        if u and u.check_password(password):
            self.current = u
            return True
        return False

    def logout(self):
        self.current = None

    def require(self, action):
        """Raise if the logged-in user may not do `action`.
        Call this at the top of every menu handler."""
        if self.current is None:
            raise PermissionError("not logged in")
        if not self.current.can(action):
            raise PermissionError(
                f"role '{self.current.role}' is not allowed to '{action}'")
        return True

    def allowed(self, action):
        """Same check but returns True/False instead of raising."""
        return self.current is not None and self.current.can(action)


class AccessMatrix:
    """matrix[(subject, object)] = {'read','write',...}"""

    def __init__(self):
        self.matrix = {}
        self.owners = {}

    def create(self, obj, owner):
        self.owners[obj] = owner
        self.matrix[(owner, obj)] = {"read", "write", "delete"}

    def grant(self, granter, subject, obj, rights):
        if self.owners.get(obj) != granter:
            raise PermissionError("only the owner can grant rights")
        self.matrix.setdefault((subject, obj), set()).update(rights)

    def revoke(self, granter, subject, obj):
        if self.owners.get(obj) != granter:
            raise PermissionError("only the owner can revoke rights")
        self.matrix.pop((subject, obj), None)

    def check(self, subject, obj, right):
        return right in self.matrix.get((subject, obj), set())


LEVELS = {"public": 0, "internal": 1, "confidential": 2, "secret": 3, "topsecret": 4}


def can_read(subject_clearance, object_classification):
    """Simple Security Property: NO READ UP."""
    return LEVELS[subject_clearance] >= LEVELS[object_classification]


def can_write(subject_clearance, object_classification):
    """*-Property: NO WRITE DOWN."""
    return LEVELS[subject_clearance] <= LEVELS[object_classification]


class TimedGrant:
    """Give a user access to one object for N hours, revocable at any time."""

    def __init__(self):
        self.grants = {}                     # (user, obj) -> expiry datetime

    def grant(self, user, obj, hours=24):
        self.grants[(user, obj)] = datetime.now() + timedelta(hours=hours)

    def revoke(self, user, obj):
        self.grants.pop((user, obj), None)

    def check(self, user, obj):
        exp = self.grants.get((user, obj))
        return exp is not None and datetime.now() < exp

    def list_active(self):
        now = datetime.now()
        return {k: v for k, v in self.grants.items() if v > now}


# ==========================================================================
### FROM c13_socket_client_server.py
# ==========================================================================

HOST, PORT = "127.0.0.1", 65432


def send_msg(sock, data):
    """Send length first, then the data."""
    if isinstance(data, str):
        data = data.encode()
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_exact(sock, n):
    """Keep reading until exactly n bytes arrive (recv can return less)."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf


def recv_msg(sock):
    """Read the 4-byte length, then that many bytes."""
    length = struct.unpack(">I", recv_exact(sock, 4))[0]
    return recv_exact(sock, length)


def run_server(host=HOST, port=PORT):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen()
        print(f"[server] listening on {host}:{port}")
        while True:
            conn, addr = s.accept()
            with conn:
                print(f"[server] client {addr} connected")
                try:
                    while True:
                        data = recv_msg(conn)
                        if data == b"BYE":
                            print("[server] client said BYE")
                            break
                        digest = hashlib.sha256(data).hexdigest()
                        print(f"[server] got {len(data)} bytes -> {digest[:16]}...")
                        send_msg(conn, digest)          # send the hash back
                except ConnectionError:
                    print("[server] client disconnected")


def run_client(messages=None, host=HOST, port=PORT, corrupt=False):
    messages = messages or ["Hello secure world", "Second message"]
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        for msg in messages:
            payload = msg.encode()
            if corrupt:
                payload = payload[:-1] + bytes([payload[-1] ^ 0x01])  # flip a bit
            send_msg(s, payload)
            received = recv_msg(s).decode()
            local = hashlib.sha256(msg.encode()).hexdigest()
            print(f"\nmessage  : {msg}")
            print(f"local    : {local}")
            print(f"server   : {received}")
            print("INTEGRITY:", "OK" if local == received else "FAILED (tampered)")
        send_msg(s, "BYE")


def run_client_multipart(message, parts=4, host=HOST, port=PORT):
    """Sends 'PART <data>' pieces then 'END'; server replies with the hash."""
    size = max(1, len(message) // parts)
    chunks = [message[i:i + size] for i in range(0, len(message), size)]
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        for c in chunks:
            send_msg(s, b"PART" + c.encode())
            print("[client] sent part:", c)
        send_msg(s, b"END")
        digest = recv_msg(s).decode()
        local = hashlib.sha256(message.encode()).hexdigest()
        print("server hash:", digest)
        print("local  hash:", local)
        print("INTEGRITY  :", "OK" if digest == local else "FAILED")
        send_msg(s, "BYE")


def run_server_multipart(host=HOST, port=PORT):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen()
        print(f"[server] multipart mode on {host}:{port}")
        while True:
            conn, addr = s.accept()
            buffer = b""
            with conn:
                try:
                    while True:
                        data = recv_msg(conn)
                        if data == b"BYE":
                            break
                        if data == b"END":
                            digest = hashlib.sha256(buffer).hexdigest()
                            print(f"[server] reassembled: {buffer.decode()}")
                            send_msg(conn, digest)
                            buffer = b""
                        elif data.startswith(b"PART"):
                            buffer += data[4:]          # strip the 'PART' tag
                except ConnectionError:
                    pass


# ============================================================================
### SELF TEST
# ============================================================================
if __name__ == "__main__":
    print("Classical  :", affine_encrypt("hello", 15, 20))
    print("DES        :", des_decrypt(des_encrypt("hi", "A1B2C3D4"), "A1B2C3D4"))
    k = rsa_generate(1024)
    print("RSA        :", rsa_decrypt(rsa_encrypt("hi", k.publickey()), k).decode())
    print("Signature  :", rsa_verify("hi", rsa_sign("hi", k), k.publickey()))
    pub, priv = elgamal_keygen(160)
    ct, m = elgamal_encrypt("hi", pub)
    print("ElGamal    :", elgamal_decrypt(ct, priv, pub, m))
    e = ecc_generate()
    print("ECC        :", ecc_decrypt(*ecc_encrypt("hi", e.public_key()), e).decode())
    n, (p, q) = rabin_keygen(512)
    print("Rabin      :", rabin_decrypt(rabin_encrypt("hi", n), p, q).decode())
    print("Hash       :", sha256_hex("hi")[:16], "custom:", custom_hash("hi"))
    print("Toolkit loaded OK")
