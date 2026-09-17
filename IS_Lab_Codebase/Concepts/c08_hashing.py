"""
CONCEPT 08 : HASHING
(Lab 5)

A hash maps any-length input -> fixed-length output.
Properties wanted: one-way (cannot invert), collision-free, avalanche
(one bit changed in input -> ~half the output bits change).

Library: hashlib (built into python - nothing to install).
  hashlib.md5 / sha1 / sha256 / sha512
  .hexdigest() -> string,  .digest() -> raw bytes
"""

import hashlib
import time
import random
import string


# ---------------------------------------------------------------------------
# 1. STANDARD HASHES
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# 2. CUSTOM HASH  (Lab 5 Exercise 1 - djb2 style)
#    start at 5381, hash = hash*33 + ord(ch), mix bits, mask to 32 bits
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# 3. HMAC - keyed hash, proves integrity AND authenticity
# ---------------------------------------------------------------------------

def hmac_sha256(key, message):
    import hmac
    key = key.encode() if isinstance(key, str) else key
    msg = message.encode() if isinstance(message, str) else message
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def hmac_verify(key, message, tag):
    import hmac
    return hmac.compare_digest(hmac_sha256(key, message), tag)  # timing-safe


# ---------------------------------------------------------------------------
# 4. PERFORMANCE + COLLISION EXPERIMENT (Lab 5 Exercise 3)
# ---------------------------------------------------------------------------

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


if __name__ == "__main__":
    print("sha256      :", sha256_hex("Hello"))
    print("custom_hash :", custom_hash("Hello"), hex(custom_hash("Hello")))
    print("hmac        :", hmac_sha256("k3y", "Hello")[:32], "...")
    ds = random_strings(100)
    for a in ("md5", "sha1", "sha256"):
        print(f"{a:7s} 100 strings in {time_hash(a, ds)*1000:.3f} ms, "
              f"collisions(full)={len(find_collisions(ds, a))}")
    avalanche_demo()
