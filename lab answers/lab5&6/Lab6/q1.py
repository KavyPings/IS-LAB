import hashlib
import random
from math import gcd

print("1. ElGamal Digital Signature")

p = 467
g = 2

x = random.randint(2, p - 2)
y = pow(g, x, p)

message = "Digital Signature"

h = int(hashlib.sha256(message.encode()).hexdigest(), 16)

while True:
    k = random.randint(2, p - 2)
    if gcd(k, p - 1) == 1:
        break

r = pow(g, k, p)
k_inv = pow(k, -1, p - 1)

s = ((h - x * r) * k_inv) % (p - 1)

print("Message:", message)
print("Public Key:", (p, g, y))
print("Private Key:", x)
print("Signature:", (r, s))

left = pow(g, h, p)
right = (pow(y, r, p) * pow(r, s, p)) % p

if left == right:
    print("ElGamal Signature Verified")
else:
    print("ElGamal Signature Invalid")


print("\n2. Schnorr Digital Signature")

p = 23
q = 11
g = 2

x = random.randint(1, q - 1)
y = pow(g, x, p)

message = "Digital Signature"

k = random.randint(1, q - 1)
r = pow(g, k, p)

e = int(
    hashlib.sha256(
        (message + str(r)).encode()
    ).hexdigest(),
    16
) % q

s = (k + x * e) % q

print("Message:", message)
print("Public Key:", y)
print("Private Key:", x)
print("Signature:", (e, s))

r_verify = (
    pow(g, s, p) *
    pow(pow(y, e, p), -1, p)
) % p

e_verify = int(
    hashlib.sha256(
        (message + str(r_verify)).encode()
    ).hexdigest(),
    16
) % q

if e == e_verify:
    print("Schnorr Signature Verified")
else:
    print("Schnorr Signature Invalid")