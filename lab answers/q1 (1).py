from math import gcd
p = 61
q = 53

n = p * q
phi = (p - 1) * (q - 1)
e = 17
d = pow(e, -1, phi)
print("Public Key  (n, e):", (n, e))
print("Private Key (n, d):", (n, d))

message = "Asymmetric Encryption"

encrypted = []

for ch in message:
    m = ord(ch)

    c = pow(m, e, n)

    encrypted.append(c)

print("\nOriginal Message :", message)
print("Encrypted Message:", encrypted)
decrypted = ""

for c in encrypted:
    m = pow(c, d, n)

    decrypted += chr(m)

print("Decrypted Message:", decrypted)