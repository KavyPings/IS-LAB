"""
LAB 3 - EXERCISE 3
ElGamal with public key (p, g, h) and private key x:
encrypt "Confidential Data", then decrypt.

CONCEPT
  keys    : private x, public h = g^x mod p
  encrypt : pick random k
            c1 = g^k mod p
            c2 = m * h^k mod p
  decrypt : s = c1^x mod p          (this equals h^k because c1^x = g^kx)
            m = c2 * s^-1 mod p

WHY IT IS SECURE: recovering x from h = g^x mod p is the discrete
logarithm problem.
WHY k MUST BE FRESH: reusing k with the same key leaks the plaintext.
"""

import random

MESSAGE = "Confidential Data"


def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x, y = egcd(b, a % b)
    return (g, y, x - (a // b) * y)


def modinv(a, m):
    g, x, _ = egcd(a % m, m)
    return x % m


def is_prime(n, k=20):
    if n < 2:
        return False
    for sp in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31):
        if n % sp == 0:
            return n == sp
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def keygen(bits=256):
    """Safe prime p = 2q+1 so that g = 2 generates a large subgroup."""
    while True:
        q = random.getrandbits(bits - 1) | (1 << (bits - 2)) | 1
        if is_prime(q) and is_prime(2 * q + 1):
            p = 2 * q + 1
            break
    g = 2
    x = random.randrange(2, p - 2)        # PRIVATE key
    h = pow(g, x, p)                      # PUBLIC key component
    return (p, g, h), x


def encrypt(m_int, pub):
    p, g, h = pub
    k = random.randrange(2, p - 2)        # fresh random k every time
    c1 = pow(g, k, p)
    c2 = (m_int * pow(h, k, p)) % p
    return c1, c2, k


def decrypt(c1, c2, x, p):
    s = pow(c1, x, p)                     # s = c1^x = g^(kx) = h^k
    return (c2 * modinv(s, p)) % p


if __name__ == "__main__":
    pub, x = keygen(256)
    p, g, h = pub
    print("p (bits)  :", p.bit_length())
    print("p         :", p)
    print("g         :", g)
    print("h = g^x   :", h)
    print("x (secret):", x)

    m = int.from_bytes(MESSAGE.encode(), "big")     # message -> integer
    print("\nmessage   :", MESSAGE)
    print("as integer:", m)
    print("m < p     :", m < p, " (required, else split the message)")

    c1, c2, k = encrypt(m, pub)
    print("\nrandom k  :", k)
    print("c1        :", c1)
    print("c2        :", c2)

    rec = decrypt(c1, c2, x, p)
    print("\nrecovered :", rec.to_bytes((rec.bit_length() + 7) // 8, "big").decode())

    c1b, c2b, _ = encrypt(m, pub)
    print("\nsame message encrypted again gives a DIFFERENT ciphertext:")
    print("  first  c1:", str(c1)[:40], "...")
    print("  second c1:", str(c1b)[:40], "... (because k is random)")
