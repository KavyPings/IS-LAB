# LAB 7 - ADDITIONAL QUESTION (manual's "secure medical diagnosis")
# Diagnose high blood pressure (> 130) without decrypting the reading.
#
# WARNING ABOUT THE MANUAL
#   The manual's listing claims ElGamal can do a homomorphic COMPARISON by
#   multiplying two ciphertexts. It cannot. Multiplying ElGamal ciphertexts
#   multiplies the plaintexts; there is no ordering information in the result,
#   and the code in the manual does not run (generate_keypair uses p as both
#   the prime and the bit length, and decrypt unpacks a tuple from an int).
#
#   What DOES work, and is what this answer implements:
#     * Paillier can SUBTRACT on encrypted data:  E(bp) * E(-threshold)
#       decrypts to bp - threshold.
#     * The hospital server computes that difference while still encrypted
#       and never learns the reading.
#     * Only the key holder (the lab that issued the key) decrypts, and it is
#       told to publish ONLY the sign of the difference, not the value.
#   That is the honest version of "secure diagnosis": the server does the
#   arithmetic blind, and exactly one bit comes out.

from Crypto.Util.number import getPrime, GCD
import random

BITS = 512
THRESHOLD = 130


def keygen(bits=BITS):
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    while p == q:
        q = getPrime(bits // 2)
    n = p * q
    return {"n": n, "nn": n * n}, (p - 1) * (q - 1)


def encrypt(pub, m):
    n, nn = pub["n"], pub["nn"]
    r = random.randrange(1, n)
    while GCD(r, n) != 1:
        r = random.randrange(1, n)
    return ((1 + (m % n) * n) * pow(r, n, nn)) % nn      # m % n handles negatives


def decrypt(pub, lam, c):
    n, nn = pub["n"], pub["nn"]
    u = (pow(c, lam, nn) - 1) // n
    m = (u * pow(lam, -1, n)) % n
    return m - n if m > n // 2 else m                    # map back to signed


def add(pub, c1, c2):
    return (c1 * c2) % pub["nn"]


def subtract_plain(pub, c, k):
    # E(m) * E(-k) = E(m - k); encrypting -k is the same as n-k
    return add(pub, c, encrypt(pub, -k))


public_key, private_key = keygen()

patients = {"P001": 118, "P002": 142, "P003": 130, "P004": 165, "P005": 96}

print("--- patients encrypt their own readings ---")
encrypted = {}
for pid, reading in patients.items():
    encrypted[pid] = encrypt(public_key, reading)
    print("%s -> %s" % (pid, hex(encrypted[pid])[:26] + "..."))
print()

print("--- the server subtracts the threshold while still encrypted ---")
print("it never decrypts anything, and it does not know any reading")
differences = {pid: subtract_plain(public_key, c, THRESHOLD)
               for pid, c in encrypted.items()}
for pid, c in differences.items():
    print("%s  E(bp - %d) = %s" % (pid, THRESHOLD, hex(c)[:26] + "..."))
print()

print("--- the key holder reveals only the SIGN of each difference ---")
print("%-6s %-12s %s" % ("ID", "diagnosis", "(true reading, shown here only to check)"))
for pid, c in differences.items():
    difference = decrypt(public_key, private_key, c)
    verdict = "HIGH blood pressure" if difference > 0 else "normal"
    print("%-6s %-12s  (%d)" % (pid, verdict, patients[pid]))
print()

print("--- the aggregate the hospital is actually allowed to publish ---")
total = encrypt(public_key, 0)
for c in encrypted.values():
    total = add(public_key, total, c)
mean = decrypt(public_key, private_key, total) // len(patients)
print("mean blood pressure over %d patients = %d" % (len(patients), mean))
print("real mean =", sum(patients.values()) // len(patients))
print()
print("What leaked: one bit per patient (above or below the threshold), plus")
print("the mean. Individual readings never left their owner in the clear.")
