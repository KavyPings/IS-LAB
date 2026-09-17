"""
LAB 2 - ADDITIONAL 1
Using DES and AES (128, 192, 256) encrypt five different messages with the
same key.
  a) consider different modes of operation
  b) plot a graph of execution time per technique
  c) compare time taken by different modes

CONCEPT: the mode of operation decides how blocks are chained.
  ECB - each block alone. Same plaintext block -> same ciphertext block. Weak.
  CBC - each block XORed with the previous ciphertext. Needs an IV.
  CFB - turns the block cipher into a self-synchronising stream cipher.
  OFB - stream cipher, keystream independent of the data.
  CTR - stream cipher, encrypts a counter. Parallelisable, fastest.

The "graph" is drawn as a text bar chart so no extra library is needed.
matplotlib is used only if it happens to be installed.
"""

import time
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

MESSAGES = [
    "Message one for encryption testing",
    "Second message with different content here",
    "Third message is a bit longer than the previous two ones",
    "Fourth",
    "Fifth message to complete the set of five test messages",
]

DES_KEY = b"DESkey01"                                   # 8 bytes
AES_KEY = b"0123456789ABCDEF0123456789ABCDEF"           # 32 bytes (slice it)
RUNS = 300


def make(algo, bits, mode_name):
    """Factory returning a fresh cipher object (they are single-use)."""
    if algo == "DES":
        key, block, M = DES_KEY, 8, DES
    else:
        key, block, M = AES_KEY[:bits // 8], 16, AES
    iv = b"\x00" * block
    modes = {
        "ECB": lambda: M.new(key, M.MODE_ECB),
        "CBC": lambda: M.new(key, M.MODE_CBC, iv),
        "CFB": lambda: M.new(key, M.MODE_CFB, iv),
        "OFB": lambda: M.new(key, M.MODE_OFB, iv),
        "CTR": lambda: M.new(key, M.MODE_CTR, nonce=b"\x00" * (block // 2)),
    }
    return modes[mode_name], block


def run(algo, bits, mode_name):
    """Encrypt + decrypt all five messages, return (enc_time, dec_time)."""
    factory, block = make(algo, bits, mode_name)
    stream = mode_name in ("CFB", "OFB", "CTR")          # no padding needed
    data = [m.encode() for m in MESSAGES]
    prepared = data if stream else [pad(d, block) for d in data]

    t0 = time.perf_counter()
    for _ in range(RUNS):
        cts = [factory().encrypt(d) for d in prepared]
    enc = (time.perf_counter() - t0) / RUNS

    t0 = time.perf_counter()
    for _ in range(RUNS):
        outs = [factory().decrypt(c) for c in cts]
    dec = (time.perf_counter() - t0) / RUNS

    recovered = outs if stream else [unpad(o, block) for o in outs]
    assert recovered == data, f"{algo}-{bits} {mode_name} round trip failed"
    return enc, dec


def bar(v, biggest, width=40):
    return "#" * max(1, int(width * v / biggest))


if __name__ == "__main__":
    techniques = [("DES", 64), ("AES", 128), ("AES", 192), ("AES", 256)]
    modes = ["ECB", "CBC", "CFB", "OFB", "CTR"]

    results = {}
    print(f"encrypting {len(MESSAGES)} messages, {RUNS} runs each\n")
    print(f"{'technique':<12}{'mode':<6}{'encrypt us':>12}{'decrypt us':>12}")
    for algo, bits in techniques:
        for m in modes:
            e, d = run(algo, bits, m)
            name = f"{algo}-{bits}" if algo == "AES" else "DES"
            results[(name, m)] = (e, d)
            print(f"{name:<12}{m:<6}{e*1e6:>12.2f}{d*1e6:>12.2f}")

    biggest = max(e for e, d in results.values())
    print("\n(b) TEXT GRAPH - encryption time per technique/mode")
    for (name, m), (e, d) in results.items():
        print(f"  {name:<9}{m:<5}{bar(e, biggest)} {e*1e6:.1f} us")

    print("\n(c) COMPARISON OF MODES")
    for m in modes:
        avg = sum(results[(n, m)][0] for n, _ in
                  [(f"{a}-{b}" if a == 'AES' else 'DES', b) for a, b in techniques]
                  ) / len(techniques)
        print(f"  {m}: average {avg*1e6:.2f} us")
    print("  * CTR/OFB/CFB avoid padding, so they process fewer bytes.")
    print("  * ECB is fastest but leaks patterns - never use it for real data.")
    print("  * CBC costs an extra XOR per block and cannot be parallelised.")
    print("  * DES is slower than AES per byte and has a much weaker key.")

    # optional real plot, only if matplotlib exists
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        labels = [f"{n}\n{m}" for n, m in results]
        vals = [e * 1e6 for e, d in results.values()]
        plt.figure(figsize=(14, 5))
        plt.bar(labels, vals)
        plt.ylabel("encryption time (us)")
        plt.title("DES vs AES across modes of operation")
        plt.tight_layout()
        plt.savefig("mode_comparison.png")
        print("\n  (matplotlib found - chart saved as mode_comparison.png)")
    except ImportError:
        print("\n  (matplotlib not installed - text chart above is the answer)")
