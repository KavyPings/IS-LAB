# LAB 7 - EXERCISE 2
# Use the MULTIPLICATIVE homomorphic property of RSA. Encrypt 7 and 3,
# print the ciphertexts, multiply them without decrypting, print the
# encrypted product, decrypt it and check that it equals 21.
#
#       E(m1) * E(m2) = m1^e * m2^e = (m1*m2)^e = E(m1*m2)   (mod n)
#
# IMPORTANT: this only works with TEXTBOOK RSA (no padding). PKCS1_OAEP
# deliberately destroys the property, which is why real RSA is not homomorphic.

from Crypto.Util.number import getPrime, GCD

BITS = 512


def generate_keypair(bits=BITS):
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    while p == q:
        q = getPrime(bits // 2)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    while GCD(e, phi) != 1:
        e += 2

    d = pow(e, -1, phi)        # modular inverse, Python 3.8+
    return (n, e), (n, d)


def encrypt(public_key, m):
    n, e = public_key
    return pow(m, e, n)        # c = m^e mod n


def decrypt(private_key, c):
    n, d = private_key
    return pow(c, d, n)        # m = c^d mod n


def homomorphic_multiply(c1, c2, public_key):
    n, e = public_key
    return (c1 * c2) % n


public_key, private_key = generate_keypair()
n, e = public_key

a = 7
b = 3

cipher_a = encrypt(public_key, a)
cipher_b = encrypt(public_key, b)

print("--- RSA key pair (textbook, no padding) ---")
print("n (hex):", hex(n))
print("e      :", e)
print()

print("--- Encryption ---")
print("a =", a, " ciphertext:", hex(cipher_a))
print("b =", b, " ciphertext:", hex(cipher_b))
print()

print("--- Homomorphic multiplication (no decryption involved) ---")
cipher_product = homomorphic_multiply(cipher_a, cipher_b, public_key)
print("E(a) * E(b) mod n:", hex(cipher_product))
print()

print("--- Decrypting the result ---")
recovered = decrypt(private_key, cipher_product)
print("decrypted product:", recovered)
print("a * b            :", a * b)
print("match            :", recovered == a * b)
print()

print("--- Why this is also a weakness ---")
print("Textbook RSA is DETERMINISTIC: the same number always encrypts to the")
print("same ciphertext, so an attacker can simply build a lookup table.")
print("E(7) run twice:", hex(encrypt(public_key, 7))[:24] + "...",
      hex(encrypt(public_key, 7))[:24] + "...")
print()
print("And the homomorphism lets an attacker forge: given E(m) they can")
print("produce E(2m) without the private key:")
forged = homomorphic_multiply(cipher_a, encrypt(public_key, 2), public_key)
print("E(a) * E(2) decrypts to", decrypt(private_key, forged), "= 2 *", a)
print()
print("Adding does NOT work: E(a) + E(b) decrypts to",
      str(decrypt(private_key, (cipher_a + cipher_b) % n))[:24] + "...  (garbage)")
