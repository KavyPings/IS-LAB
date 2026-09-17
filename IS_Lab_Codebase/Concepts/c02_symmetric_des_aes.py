"""
CONCEPT 02 : SYMMETRIC BLOCK CIPHERS - DES, 3DES, AES
(Lab 2 - Advanced Symmetric Key Ciphers)

Library : pycryptodome      ->  pip install pycryptodome
Import  : from Crypto.Cipher import DES, DES3, AES

KEY SIZE CHEAT SHEET
  DES      : exactly  8 bytes
  3DES     : 16 or 24 bytes (k1 != k2 required by the library)
  AES-128  : 16 bytes
  AES-192  : 24 bytes
  AES-256  : 32 bytes

BLOCK SIZE
  DES/3DES : 8 bytes   AES : 16 bytes
  -> plaintext must be padded to a multiple of the block size (ECB/CBC).
  -> CTR/CFB/OFB are STREAM modes, no padding needed.
"""

from Crypto.Cipher import DES, DES3, AES
from Crypto.Util.Padding import pad, unpad      # PKCS#7 padding
from Crypto.Random import get_random_bytes


# ---------------------------------------------------------------------------
# KEY PREPARATION - the single thing that breaks most exam answers
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# DES  (8-byte key, 8-byte block)
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# TRIPLE DES  (16 or 24 byte key)
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# AES  (key size decides AES-128 / 192 / 256)
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# AES KEY EXPANSION shown step by step (asked in Lab2 Q5 "show all steps")
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# TIMING HELPER (used by every "compare performance" question)
# ---------------------------------------------------------------------------

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


if __name__ == "__main__":
    ct = des_encrypt("Confidential Data", "A1B2C3D4")
    print("DES  :", ct.hex(), "->", des_decrypt(ct, "A1B2C3D4").decode())
    ct = aes_encrypt("Sensitive Information", "0123456789ABCDEF0123456789ABCDEF", 128)
    print("AES128:", ct.hex(), "->", aes_decrypt(ct, "0123456789ABCDEF0123456789ABCDEF", 128).decode())
    ct = des3_encrypt("Classified Text", "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF")
    print("3DES :", ct.hex(), "->", des3_decrypt(ct, "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF").decode())
    print_round_keys(make_key("FEDCBA9876543210FEDCBA9876543210", 24))
