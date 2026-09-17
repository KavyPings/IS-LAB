"""
LAB 2 - EXERCISE 3
Compare encryption and decryption times for DES and AES-256 using the
message "Performance Testing of Encryption Algorithms".

CONCEPT: performance measurement.
  - one run is too short to measure -> repeat N times and take the average
  - use time.perf_counter() (high resolution), never time.time()
  - AES is usually FASTER than DES even though its key is longer, because
    AES is designed for 32-bit word operations and often uses CPU AES-NI
    instructions, while DES does bit-level permutations.
"""

import time
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad

MESSAGE = "Performance Testing of Encryption Algorithms"
DES_KEY = b"8bytekey"                       # 8 bytes
AES_KEY = b"0123456789ABCDEF0123456789ABCDEF"   # 32 bytes -> AES-256
RUNS = 2000


def measure(cipher_factory, block, data, runs=RUNS):
    """Returns (ciphertext, encrypt_seconds, decrypt_seconds) averaged."""
    padded = pad(data, block)

    t0 = time.perf_counter()
    for _ in range(runs):
        ct = cipher_factory().encrypt(padded)      # new object each time
    enc = (time.perf_counter() - t0) / runs

    t0 = time.perf_counter()
    for _ in range(runs):
        pt = unpad(cipher_factory().decrypt(ct), block)
    dec = (time.perf_counter() - t0) / runs

    assert pt == data                              # correctness check
    return ct, enc, dec


def bar(value, biggest, width=40):
    """Tiny text bar chart so no plotting library is needed."""
    return "#" * max(1, int(width * value / biggest))


if __name__ == "__main__":
    data = MESSAGE.encode()
    print("message:", MESSAGE)
    print("runs   :", RUNS, "\n")

    results = {}
    ct, e, d = measure(lambda: DES.new(DES_KEY, DES.MODE_ECB), 8, data)
    results["DES (56-bit)"] = (e, d, ct)
    ct, e, d = measure(lambda: AES.new(AES_KEY, AES.MODE_ECB), 16, data)
    results["AES-256"] = (e, d, ct)

    print(f"{'algorithm':<16}{'encrypt (us)':>14}{'decrypt (us)':>14}{'ct bytes':>10}")
    for name, (e, d, c) in results.items():
        print(f"{name:<16}{e*1e6:>14.3f}{d*1e6:>14.3f}{len(c):>10}")

    biggest = max(max(e, d) for e, d, _ in results.values())
    print("\ntext chart (longer bar = slower):")
    for name, (e, d, _) in results.items():
        print(f"  {name:<14} enc {bar(e, biggest)}")
        print(f"  {'':<14} dec {bar(d, biggest)}")

    print("\nFINDINGS")
    print("  * AES-256 handles 16 bytes per block, DES only 8, so AES needs")
    print("    fewer block operations for the same message.")
    print("  * AES is typically faster per byte despite the larger key.")
    print("  * DES's 56-bit key is brute-forceable today; AES-256 is not.")
    print("  * Conclusion: AES is better in BOTH speed and security.")
