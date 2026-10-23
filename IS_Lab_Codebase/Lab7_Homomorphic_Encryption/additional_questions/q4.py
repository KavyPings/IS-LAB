# LAB 7 - ADDITIONAL QUESTION 1d
# Performance analysis: compare Paillier, ElGamal and textbook RSA for
# key generation, encryption, decryption and the homomorphic operation.
#
# Same key size for all three so the comparison is fair.

from Crypto.Util.number import getPrime, GCD
import random
import time

BITS = 512
ROUNDS = 30                    # how many operations to average over


def timed(label, function, rounds=ROUNDS):
    start = time.perf_counter()
    for _ in range(rounds):
        result = function()
    elapsed = (time.perf_counter() - start) / rounds
    return label, elapsed * 1000, result        # milliseconds per operation


# ---------------- Paillier : additive ----------------

def paillier_keygen():
    p = getPrime(BITS // 2)
    q = getPrime(BITS // 2)
    while p == q:
        q = getPrime(BITS // 2)
    n = p * q
    return {"n": n, "nn": n * n, "lam": (p - 1) * (q - 1)}


def paillier_encrypt(key, m):
    n, nn = key["n"], key["nn"]
    r = random.randrange(1, n)
    while GCD(r, n) != 1:
        r = random.randrange(1, n)
    return ((1 + m * n) * pow(r, n, nn)) % nn


def paillier_decrypt(key, c):
    n, nn, lam = key["n"], key["nn"], key["lam"]
    u = (pow(c, lam, nn) - 1) // n
    return (u * pow(lam, -1, n)) % n


# ---------------- ElGamal : multiplicative ----------------

def elgamal_keygen():
    p = getPrime(BITS)
    g = 2
    x = random.randrange(2, p - 2)
    return {"p": p, "g": g, "y": pow(g, x, p), "x": x}


def elgamal_encrypt(key, m):
    p, g, y = key["p"], key["g"], key["y"]
    r = random.randrange(2, p - 2)
    return (pow(g, r, p), (m * pow(y, r, p)) % p)


def elgamal_decrypt(key, c):
    p = key["p"]
    return (c[1] * pow(c[0], -key["x"], p)) % p


# ---------------- textbook RSA : multiplicative ----------------

def rsa_keygen():
    p = getPrime(BITS // 2)
    q = getPrime(BITS // 2)
    while p == q:
        q = getPrime(BITS // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    while GCD(e, phi) != 1:
        e += 2
    return {"n": n, "e": e, "d": pow(e, -1, phi)}


def rsa_encrypt(key, m):
    return pow(m, key["e"], key["n"])


def rsa_decrypt(key, c):
    return pow(c, key["d"], key["n"])


# ---------------- run the benchmark ----------------

print("=" * 72)
print(" PHE PERFORMANCE COMPARISON   key size %d bits, %d rounds each"
      % (BITS, ROUNDS))
print("=" * 72)

rows = []

# key generation (only a few rounds, it is the slow part)
_, t_pail_key, pail = timed("paillier keygen", paillier_keygen, 5)
_, t_elg_key, elg = timed("elgamal keygen", elgamal_keygen, 5)
_, t_rsa_key, rsa = timed("rsa keygen", rsa_keygen, 5)

m1, m2 = 123, 456

_, t_pail_enc, c_pail = timed("x", lambda: paillier_encrypt(pail, m1))
_, t_elg_enc, c_elg = timed("x", lambda: elgamal_encrypt(elg, m1))
_, t_rsa_enc, c_rsa = timed("x", lambda: rsa_encrypt(rsa, m1))

_, t_pail_dec, _ = timed("x", lambda: paillier_decrypt(pail, c_pail))
_, t_elg_dec, _ = timed("x", lambda: elgamal_decrypt(elg, c_elg))
_, t_rsa_dec, _ = timed("x", lambda: rsa_decrypt(rsa, c_rsa))

c_pail2 = paillier_encrypt(pail, m2)
c_elg2 = elgamal_encrypt(elg, m2)
c_rsa2 = rsa_encrypt(rsa, m2)

_, t_pail_op, _ = timed("x", lambda: (c_pail * c_pail2) % pail["nn"])
_, t_elg_op, _ = timed("x", lambda: ((c_elg[0] * c_elg2[0]) % elg["p"],
                                     (c_elg[1] * c_elg2[1]) % elg["p"]))
_, t_rsa_op, _ = timed("x", lambda: (c_rsa * c_rsa2) % rsa["n"])

print()
print("%-10s %12s %12s %12s %12s" % ("scheme", "keygen ms", "encrypt ms",
                                     "decrypt ms", "hom.op ms"))
print("-" * 72)
print("%-10s %12.2f %12.3f %12.3f %12.5f"
      % ("Paillier", t_pail_key, t_pail_enc, t_pail_dec, t_pail_op))
print("%-10s %12.2f %12.3f %12.3f %12.5f"
      % ("ElGamal", t_elg_key, t_elg_enc, t_elg_dec, t_elg_op))
print("%-10s %12.2f %12.3f %12.3f %12.5f"
      % ("RSA", t_rsa_key, t_rsa_enc, t_rsa_dec, t_rsa_op))
print()

print("%-10s %14s %16s %14s" % ("scheme", "operation", "ciphertext size",
                                "randomised"))
print("-" * 72)
print("%-10s %14s %16s %14s" % ("Paillier", "addition",
                                str(pail["nn"].bit_length()) + " bits", "yes"))
print("%-10s %14s %16s %14s" % ("ElGamal", "multiplication",
                                str(2 * elg["p"].bit_length()) + " bits (pair)", "yes"))
print("%-10s %14s %16s %14s" % ("RSA", "multiplication",
                                str(rsa["n"].bit_length()) + " bits", "NO"))
print()

print("--- reading the numbers ---")
print("* Paillier ciphertexts live mod n^2, so they are twice the size of the")
print("  modulus and every operation costs more than RSA at the same bit level.")
print("* ElGamal ciphertexts are a PAIR, so also double size, but encryption is")
print("  cheap and decryption needs only one exponentiation.")
print("* RSA encryption with e = 65537 is the fastest of the three, and")
print("  decryption the slowest, because d is full size.")
print("* The homomorphic step itself is a single multiplication in every")
print("  scheme - microseconds. The cost is always in encrypt/decrypt.")
print("* Paillier is the only one of the three that ADDS, which is why every")
print("  vote-tallying or sum-of-salaries question uses it.")
