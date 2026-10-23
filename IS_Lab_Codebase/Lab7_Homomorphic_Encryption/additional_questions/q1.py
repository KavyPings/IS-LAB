# LAB 7 - ADDITIONAL QUESTION 1a
# Homomorphic MULTIPLICATION with ElGamal.
#
# ElGamal ciphertext is a pair (a, b) = (g^r, m * y^r).
# Multiply the pairs component by component:
#       (a1*a2, b1*b2) = (g^(r1+r2), m1*m2 * y^(r1+r2))
# which is a valid encryption of m1*m2. So ElGamal multiplies, it does NOT add.

from Crypto.Util.number import getPrime
import random

BITS = 512


def generate_keypair(bits=BITS):
    p = getPrime(bits)
    g = 2
    x = random.randrange(2, p - 2)          # private key
    y = pow(g, x, p)                        # public key
    return (p, g, y), x


def encrypt(public_key, m):
    p, g, y = public_key
    r = random.randrange(2, p - 2)
    a = pow(g, r, p)
    b = (m * pow(y, r, p)) % p
    return (a, b)


def decrypt(public_key, private_key, cipher):
    p, g, y = public_key
    a, b = cipher
    return (b * pow(a, -private_key, p)) % p


def homomorphic_multiply(c1, c2, public_key):
    p, g, y = public_key
    return ((c1[0] * c2[0]) % p, (c1[1] * c2[1]) % p)


def homomorphic_power(c, k, public_key):
    # raising both components to k encrypts m^k
    p, g, y = public_key
    return (pow(c[0], k, p), pow(c[1], k, p))


public_key, private_key = generate_keypair()
p, g, y = public_key

a = 12
b = 7

cipher_a = encrypt(public_key, a)
cipher_b = encrypt(public_key, b)

print("--- ElGamal key pair ---")
print("p (hex):", hex(p))
print("g      :", g)
print("y (hex):", hex(y))
print()

print("--- Encryption (each ciphertext is a PAIR) ---")
print("a =", a, "-> (a1, b1) = (" + hex(cipher_a[0])[:20] + "..., "
      + hex(cipher_a[1])[:20] + "...)")
print("b =", b, "-> (a2, b2) = (" + hex(cipher_b[0])[:20] + "..., "
      + hex(cipher_b[1])[:20] + "...)")
print()

print("--- Homomorphic multiplication ---")
cipher_product = homomorphic_multiply(cipher_a, cipher_b, public_key)
print("component-wise product:", hex(cipher_product[1])[:28] + "...")
recovered = decrypt(public_key, private_key, cipher_product)
print("decrypted product:", recovered, " a * b =", a * b,
      " match:", recovered == a * b)
print()

print("--- Encrypted exponentiation comes free ---")
cubed = homomorphic_power(cipher_a, 3, public_key)
print("E(a)^3 decrypts to", decrypt(public_key, private_key, cubed),
      " a^3 =", a ** 3)
print()

print("--- What ElGamal canNOT do ---")
added = ((cipher_a[0] * cipher_b[0]) % p, (cipher_a[1] + cipher_b[1]) % p)
print("trying to add gives", str(decrypt(public_key, private_key, added))[:24]
      + "...  - not", a + b)
print("For ADDITION on encrypted data you need Paillier (exercise 1).")
print()
print("--- Side by side ---")
print("  Paillier : multiply ciphertexts -> ADD plaintexts")
print("  ElGamal  : multiply ciphertexts -> MULTIPLY plaintexts")
print("  RSA      : multiply ciphertexts -> MULTIPLY plaintexts (but deterministic)")
