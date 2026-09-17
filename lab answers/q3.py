from random import randint
p = 7919
g = 2

x = 2999

h = pow(g, x, p)

print("Public Key  (p, g, h):", (p, g, h))
print("Private Key x:", x)

message = "Confidential Data"

plaintext = [ord(ch) for ch in message]

print("\nOriginal Message:", message)

k = randint(1, p - 2)

c1 = pow(g, k, p)

s = pow(h, k, p)

ciphertext = []

for m in plaintext:
    c2 = (m * s) % p
    ciphertext.append(c2)

print("\n----- Encryption -----")
print("Random k:", k)
print("c1:", c1)
print("Ciphertext:", (c1, ciphertext))

s = pow(c1, x, p)

s_inverse = pow(s, -1, p)

decrypted = ""

for c2 in ciphertext:
    m = (c2 * s_inverse) % p
    decrypted += chr(m)

print("\n----- Decryption -----")
print("Decrypted Message:", decrypted)