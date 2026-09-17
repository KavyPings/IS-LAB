"""
CONCEPT 12 : CONVERSIONS, ENCODING, FILE / RECORD STORAGE
(needed in every single lab - this is the "glue" file)

Most lost marks come from type errors: str vs bytes vs int vs hex.
This file has one-liners for every conversion you will need.
"""

import base64
import json
import os
from datetime import datetime


# ===========================================================================
# 1. STRING <-> BYTES
# ===========================================================================

def s2b(s):
    """str -> bytes"""
    return s.encode("utf-8")


def b2s(b):
    """bytes -> str (use errors='replace' if the bytes are not real text)"""
    return b.decode("utf-8", errors="replace")


# ===========================================================================
# 2. BYTES <-> HEX      (how you PRINT ciphertext)
# ===========================================================================

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


# ===========================================================================
# 3. BYTES <-> BASE64   (safe way to store ciphertext in a text file / JSON)
# ===========================================================================

def b2b64(b):
    return base64.b64encode(b).decode()


def b642b(s):
    return base64.b64decode(s)


# ===========================================================================
# 4. BYTES <-> INT      (needed for textbook RSA / ElGamal / Rabin)
# ===========================================================================

def b2i(b):
    return int.from_bytes(b, "big")


def i2b(i):
    return i.to_bytes((i.bit_length() + 7) // 8 or 1, "big")


# ===========================================================================
# 5. BINARY / BIT OPERATIONS
# ===========================================================================

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


# ===========================================================================
# 6. PADDING (manual version, in case you cannot import Crypto.Util.Padding)
# ===========================================================================

def pkcs7_pad(data, block=8):
    n = block - (len(data) % block)
    return data + bytes([n]) * n             # pad byte value = number of pad bytes


def pkcs7_unpad(data):
    return data[:-data[-1]]


# ===========================================================================
# 7. STORING RECORDS  (every scenario question says "use any file or database")
# ===========================================================================

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


# ===========================================================================
# 8. PRETTY PRINTING (makes the output look like a real system in the demo)
# ===========================================================================

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


if __name__ == "__main__":
    data = b"Hello"
    print("hex     :", b2hex(data))
    print("spaced  :", hex_spaced(data))
    print("base64  :", b2b64(data))
    print("int     :", b2i(data), "->", i2b(b2i(data)))
    print("binary  :", to_binary("AB"))
    print("xor     :", xor_bytes(b"Hello", b"key").hex())
    print("padded  :", pkcs7_pad(b"Hello"), "->", pkcs7_unpad(pkcs7_pad(b"Hello")))
    db = JsonStore("/tmp/demo_store.json")
    db.clear()
    db.add("records", {"user": "kavy", "ct": b2b64(data), "ts": now()})
    print("store   :", db.all("records"))
