"""
LAB 5 - EXERCISE 3
Analyse MD5, SHA-1 and SHA-256 for
  * computation time
  * collision resistance
Generate a dataset of 50-100 random strings, hash them with each algorithm,
measure the time, and run collision detection on the results.

KEY POINT ABOUT COLLISIONS
  Full-length MD5/SHA-1/SHA-256 will NEVER collide on 100 random strings -
  the space is far too big. To SEE the birthday effect you must truncate
  the digest. This script does both:
     (a) collision check on the full digests  -> expect 0
     (b) collision check on truncated digests -> collisions appear
  That truncation experiment is what actually demonstrates the concept.
"""

import hashlib
import random
import string
import time

ALGOS = ["md5", "sha1", "sha256"]


def random_dataset(count=100, min_len=10, max_len=40):
    """Between 50 and 100 random strings, as the question asks."""
    pool = string.ascii_letters + string.digits
    return ["".join(random.choices(pool, k=random.randint(min_len, max_len)))
            for _ in range(count)]


def hash_all(dataset, algo):
    """Hash the whole dataset, return (digests, seconds taken)."""
    start = time.perf_counter()
    digests = [hashlib.new(algo, s.encode()).hexdigest() for s in dataset]
    return digests, time.perf_counter() - start


def detect_collisions(dataset, digests):
    """Two DIFFERENT inputs producing the SAME digest = a collision."""
    seen, collisions = {}, []
    for s, d in zip(dataset, digests):
        if d in seen and seen[d] != s:
            collisions.append((seen[d], s, d))
        seen[d] = s
    return collisions


def truncated_collisions(dataset, algo, bits):
    """Shorten each digest to `bits` bits to make collisions observable."""
    chars = bits // 4                       # 1 hex character = 4 bits
    seen, collisions = {}, []
    for s in dataset:
        d = hashlib.new(algo, s.encode()).hexdigest()[:chars]
        if d in seen and seen[d] != s:
            collisions.append((seen[d], s, d))
        seen[d] = s
    return collisions


def bar(v, biggest, width=40):
    return "#" * max(1, int(width * v / biggest))


if __name__ == "__main__":
    data = random_dataset(100)
    print(f"dataset: {len(data)} random strings")
    print("sample :", data[:3], "\n")

    print("=== (1) COMPUTATION TIME ===")
    results = {}
    for algo in ALGOS:
        digests, t = hash_all(data, algo)
        results[algo] = (t, digests)
        print(f"  {algo:<8} digest {len(digests[0])*4:3d} bits | "
              f"{t*1e6:9.2f} us total | {t/len(data)*1e9:8.1f} ns per string")

    biggest = max(t for t, _ in results.values())
    print("\n  speed chart (longer = slower):")
    for algo, (t, _) in results.items():
        print(f"    {algo:<8}{bar(t, biggest)}")

    print("\n=== (2) COLLISION DETECTION ON FULL DIGESTS ===")
    for algo, (t, digests) in results.items():
        c = detect_collisions(data, digests)
        print(f"  {algo:<8}: {len(c)} collisions "
              f"(expected 0 - the digest space is astronomically large)")

    print("\n=== (3) TRUNCATED DIGESTS - the birthday effect ===")
    print(f"  {'algo':<8}{'16 bit':>10}{'20 bit':>10}{'24 bit':>10}{'32 bit':>10}")
    big = random_dataset(2000)
    for algo in ALGOS:
        row = [len(truncated_collisions(big, algo, b)) for b in (16, 20, 24, 32)]
        print(f"  {algo:<8}{row[0]:>10}{row[1]:>10}{row[2]:>10}{row[3]:>10}")
    print(f"  (dataset of {len(big)} strings; with n bits you expect a")
    print("   collision after about 2^(n/2) inputs - the birthday bound)")

    print("\n=== FINDINGS ===")
    print("""  SPEED
    MD5 is fastest, SHA-1 close behind, SHA-256 slowest - the digest is
    longer and the compression function does more work per block.

  COLLISION RESISTANCE
    MD5    : BROKEN. Practical collisions since 2004; two different files
             with the same MD5 can be produced in seconds.
    SHA-1  : BROKEN. The SHAttered attack (2017) produced two PDFs with the
             same SHA-1 digest.
    SHA-256: no collision known; 2^128 work by the birthday bound.

  CONCLUSION
    Never use MD5 or SHA-1 for signatures, certificates or password
    storage. MD5 is acceptable only as a non-security checksum.
    Use SHA-256 (or SHA-3) whenever integrity matters - the small speed
    cost is irrelevant next to being breakable.""")
