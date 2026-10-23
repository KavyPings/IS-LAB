# LAB 7 - ADDITIONAL QUESTION 1b
# Secure data sharing with Paillier.
#
# Two hospitals each hold patient counts they are not allowed to reveal.
# A regulator wants the TOTAL, and the average, and the total for one age
# group - without ever seeing a single hospital's numbers.
#
# Only the regulator holds the private key. Both hospitals encrypt with the
# regulator's public key, the server adds the ciphertexts, and the regulator
# decrypts one number at the end.

from Crypto.Util.number import getPrime, GCD
import random

BITS = 512


def keygen(bits=BITS):
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    while p == q:
        q = getPrime(bits // 2)
    n = p * q
    return {"n": n, "g": n + 1, "nn": n * n}, (p - 1) * (q - 1)


def encrypt(pub, m):
    n, nn = pub["n"], pub["nn"]
    r = random.randrange(1, n)
    while GCD(r, n) != 1:
        r = random.randrange(1, n)
    return ((1 + m * n) * pow(r, n, nn)) % nn


def decrypt(pub, lam, c):
    n, nn = pub["n"], pub["nn"]
    u = (pow(c, lam, nn) - 1) // n
    return (u * pow(lam, -1, n)) % n


def add(pub, *ciphers):
    total = encrypt(pub, 0)
    for c in ciphers:
        total = (total * c) % pub["nn"]
    return total


def scale(pub, c, k):
    return pow(c, k, pub["nn"])


# ---------- the regulator publishes a public key ----------
public_key, private_key = keygen()
print("regulator public key n (hex):", hex(public_key["n"])[:34] + "...")
print()

# ---------- each hospital encrypts its own private numbers ----------
hospital_a = {"under_18": 120, "adult": 840, "senior": 310}
hospital_b = {"under_18": 95, "adult": 1120, "senior": 505}

encrypted_a = {k: encrypt(public_key, v) for k, v in hospital_a.items()}
encrypted_b = {k: encrypt(public_key, v) for k, v in hospital_b.items()}

print("--- what each hospital sends (nothing readable) ---")
for group in hospital_a:
    print("%-9s A: %s   B: %s" % (group,
          hex(encrypted_a[group])[:18] + "...", hex(encrypted_b[group])[:18] + "..."))
print()

# ---------- the server combines without any key ----------
print("--- the server adds ciphertexts; it holds NO key ---")
combined = {g: add(public_key, encrypted_a[g], encrypted_b[g]) for g in hospital_a}
grand_total = add(public_key, *combined.values())
print("combined senior ciphertext:", hex(combined["senior"])[:30] + "...")
print("grand total ciphertext    :", hex(grand_total)[:30] + "...")
print()

# ---------- only the regulator decrypts, and only the totals ----------
print("--- the regulator decrypts the aggregates ---")
for group in hospital_a:
    value = decrypt(public_key, private_key, combined[group])
    print("%-9s total = %5d   (check %d + %d = %d)"
          % (group, value, hospital_a[group], hospital_b[group],
             hospital_a[group] + hospital_b[group]))

total = decrypt(public_key, private_key, grand_total)
print("all patients      =", total,
      " (check", sum(hospital_a.values()) + sum(hospital_b.values()), ")")
print()

# ---------- weighted sums also work ----------
print("--- a weighted figure, still on encrypted data ---")
# cost model: 200 per child, 150 per adult, 400 per senior
weighted = add(public_key,
               scale(public_key, combined["under_18"], 200),
               scale(public_key, combined["adult"], 150),
               scale(public_key, combined["senior"], 400))
expected = (215 * 200) + (1960 * 150) + (815 * 400)
print("encrypted cost estimate:", decrypt(public_key, private_key, weighted),
      " expected:", expected)
print()
print("What was protected: no party ever saw another party's row.")
print("What leaked: the number of participants and the aggregate itself.")
