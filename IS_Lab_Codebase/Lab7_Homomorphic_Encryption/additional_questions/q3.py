# LAB 7 - ADDITIONAL QUESTION 1c
# Secure thresholding: several authorities must cooperate before anything
# can be decrypted. No single one of them can read the result alone.
#
# Scheme used here:
#   * Paillier gives additive homomorphism, so the server can total the votes.
#   * The Paillier private exponent is split with SHAMIR SECRET SHARING into
#     n shares, and any t of them reconstruct it. Fewer than t learn nothing.

from Crypto.Util.number import getPrime, GCD
import random

BITS = 512
THRESHOLD_T = 3                # how many authorities must cooperate
THRESHOLD_N = 5                # how many authorities exist


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
    return ((1 + m * n) * pow(r, n, nn)) % nn


def decrypt(pub, lam, c):
    n, nn = pub["n"], pub["nn"]
    u = (pow(c, lam, nn) - 1) // n
    return (u * pow(lam, -1, n)) % n


def add(pub, c1, c2):
    return (c1 * c2) % pub["nn"]


# ---------- Shamir secret sharing over a prime field ----------

def split_secret(secret, t, n, prime):
    # f(0) = secret, t-1 random coefficients above it
    coeffs = [secret] + [random.randrange(1, prime) for _ in range(t - 1)]
    return [(i, sum(c * pow(i, j, prime) for j, c in enumerate(coeffs)) % prime)
            for i in range(1, n + 1)]


def combine_shares(shares, prime):
    # Lagrange interpolation evaluated at x = 0
    total = 0
    for xi, yi in shares:
        num, den = 1, 1
        for xj, _ in shares:
            if xi != xj:
                num = (num * -xj) % prime
                den = (den * (xi - xj)) % prime
        total = (total + yi * num * pow(den, -1, prime)) % prime
    return total


public_key, private_exponent = keygen()
prime = getPrime(private_exponent.bit_length() + 16)      # field must hold it
shares = split_secret(private_exponent, THRESHOLD_T, THRESHOLD_N, prime)

print("--- setup ---")
print("authorities        :", THRESHOLD_N)
print("needed to decrypt  :", THRESHOLD_T)
for index, value in shares:
    print("  authority %d share : %s" % (index, hex(value)[:22] + "..."))
print()

# ---------- five parties contribute private numbers ----------
salaries = [52000, 61000, 48000, 95000, 73000]
print("--- five employees submit encrypted salaries ---")
total_cipher = encrypt(public_key, 0)
for i, salary in enumerate(salaries, 1):
    c = encrypt(public_key, salary)
    total_cipher = add(public_key, total_cipher, c)
    print("  employee %d ciphertext: %s" % (i, hex(c)[:20] + "..."))
print("combined ciphertext    :", hex(total_cipher)[:28] + "...")
print()

# ---------- too few shares ----------
print("--- %d authorities try alone ---" % (THRESHOLD_T - 1))
partial = combine_shares(shares[:THRESHOLD_T - 1], prime)
print("reconstructed exponent:", hex(partial)[:24] + "...")
print("real exponent         :", hex(private_exponent)[:24] + "...")
print("they got it right     :", partial == private_exponent)
print("decryption with it    :", str(decrypt(public_key, partial, total_cipher))[:24]
      + "...   (meaningless)")
print()

# ---------- enough shares ----------
print("--- %d authorities cooperate ---" % THRESHOLD_T)
chosen = random.sample(shares, THRESHOLD_T)
print("shares used           :", [i for i, _ in chosen])
recovered = combine_shares(chosen, prime)
print("they got it right     :", recovered == private_exponent)
payroll = decrypt(public_key, recovered, total_cipher)
print("total payroll         :", payroll)
print("real sum              :", sum(salaries))
print("average               :", payroll // len(salaries))
print()
print("Any %d of the %d shares work - try a different sample:" % (THRESHOLD_T, THRESHOLD_N))
other = random.sample(shares, THRESHOLD_T)
print("shares", [i for i, _ in other], "->",
      decrypt(public_key, combine_shares(other, prime), total_cipher))
print()
print("No individual salary was ever decrypted, and no single authority")
print("could have decrypted anything on its own.")
