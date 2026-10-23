# LAB 7 - EXERCISE 1
# Implement the Paillier encryption scheme. Encrypt 15 and 25, print the
# ciphertexts, add them WITHOUT decrypting, print the encrypted sum, then
# decrypt and check that it equals 40.
#
# Paillier is ADDITIVELY homomorphic:
#       E(m1) * E(m2) mod n^2   decrypts to   m1 + m2
# Multiplying ciphertexts adds the plaintexts. That is the whole trick.

from Crypto.Util.number import getPrime, GCD
import random

BITS = 512                     # size of n; 512 is plenty for a lab


def generate_keypair(bits=BITS):
    # two distinct primes of the same size
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    while p == q:
        q = getPrime(bits // 2)

    n = p * q
    g = n + 1                  # the standard choice; makes encryption cheap
    lam = (p - 1) * (q - 1)    # Carmichael-style private exponent
    mu = pow(lam, -1, n)

    public_key = (n, g)
    private_key = (lam, mu, n)
    return public_key, private_key


def encrypt(public_key, m):
    # c = g^m * r^n mod n^2, and with g = n+1 the first part is just (1 + m*n)
    n, g = public_key
    nn = n * n

    r = random.randrange(1, n)
    while GCD(r, n) != 1:      # r must be invertible mod n
        r = random.randrange(1, n)

    return ((1 + m * n) * pow(r, n, nn)) % nn


def decrypt(private_key, c):
    lam, mu, n = private_key
    nn = n * n
    u = (pow(c, lam, nn) - 1) // n      # the L() function from the lecture
    return (u * mu) % n


def homomorphic_add(c1, c2, public_key):
    n, g = public_key
    return (c1 * c2) % (n * n)


def homomorphic_add_constant(c, k, public_key):
    # adding a PLAIN number to an encrypted one: multiply by g^k
    n, g = public_key
    return (c * pow(g, k, n * n)) % (n * n)


def homomorphic_multiply_constant(c, k, public_key):
    # multiplying an encrypted number by a PLAIN number: raise to the power k
    n, g = public_key
    return pow(c, k, n * n)


public_key, private_key = generate_keypair()
n, g = public_key

a = 15
b = 25

cipher_a = encrypt(public_key, a)
cipher_b = encrypt(public_key, b)

print("--- Paillier key pair ---")
print("n (hex)        :", hex(n))
print("g              : n + 1")
print()

print("--- Encryption ---")
print("a              :", a)
print("Ciphertext of a:", hex(cipher_a))
print()
print("b              :", b)
print("Ciphertext of b:", hex(cipher_b))
print()

print("--- Homomorphic addition (no decryption involved) ---")
cipher_sum = homomorphic_add(cipher_a, cipher_b, public_key)
print("E(a) * E(b) mod n^2:", hex(cipher_sum))
print()

print("--- Decrypting the result ---")
recovered = decrypt(private_key, cipher_sum)
print("decrypted sum  :", recovered)
print("a + b          :", a + b)
print("match          :", recovered == a + b)
print()

print("--- Two more properties worth knowing ---")
print("E(a) + 100 plain  ->", decrypt(private_key,
      homomorphic_add_constant(cipher_a, 100, public_key)), "(expected", a + 100, ")")
print("E(a) * 3 plain    ->", decrypt(private_key,
      homomorphic_multiply_constant(cipher_a, 3, public_key)), "(expected", a * 3, ")")
print()
print("Note: E(a) * E(b) does NOT give a*b. Paillier adds only.")
print("Note: encrypting 15 twice gives different ciphertexts, because r is")
print("      random every time - that is what makes Paillier semantically secure.")
print("same plaintext, two runs:", hex(encrypt(public_key, 15))[:20] + "...",
      hex(encrypt(public_key, 15))[:20] + "...")
