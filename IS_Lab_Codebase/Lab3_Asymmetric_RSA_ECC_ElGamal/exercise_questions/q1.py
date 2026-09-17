"""
LAB 3 - EXERCISE 1
Using RSA, encrypt "Asymmetric Encryption" with the public key (n, e),
then decrypt with the private key (n, d).

CONCEPT
  key generation : n = p*q, phi = (p-1)(q-1), pick e coprime to phi,
                   d = e^-1 mod phi
  encryption     : c = m^e mod n   (public key)
  decryption     : m = c^d mod n   (private key)

TWO IMPLEMENTATIONS ARE SHOWN
  A) library RSA with OAEP padding - what you use for real messages
  B) the raw maths with our own primes - what you write if the question
     says "show the key generation steps"
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

MESSAGE = "Asymmetric Encryption"


# ============================ A) LIBRARY RSA ===============================
def library_rsa():
    key = RSA.generate(2048)                    # p, q, n, e, d all computed
    public = key.publickey()

    print("n (first 60 digits):", str(key.n)[:60], "...")
    print("e                  :", key.e)
    print("d (first 60 digits):", str(key.d)[:60], "...")
    print("key size           :", key.size_in_bits(), "bits")

    ct = PKCS1_OAEP.new(public).encrypt(MESSAGE.encode())   # c = m^e mod n
    print("\nciphertext (hex)   :", ct.hex()[:80], "...")
    print("ciphertext length  :", len(ct), "bytes")

    pt = PKCS1_OAEP.new(key).decrypt(ct)                    # m = c^d mod n
    print("decrypted          :", pt.decode())
    return pt.decode() == MESSAGE


# ========================= B) RAW RSA MATHS ================================
def egcd(a, b):
    """Extended Euclid -> used to compute d = e^-1 mod phi."""
    if b == 0:
        return (a, 1, 0)
    g, x, y = egcd(b, a % b)
    return (g, y, x - (a // b) * y)


def modinv(a, m):
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError("no inverse")
    return x % m


def manual_rsa():
    # two primes, small enough to print but big enough to hold the message
    p = 1000003
    q = 1000033
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = modinv(e, phi)

    print("p   =", p)
    print("q   =", q)
    print("n   = p*q =", n)
    print("phi = (p-1)(q-1) =", phi)
    print("e   =", e, " (gcd(e,phi) =", egcd(e, phi)[0], ")")
    print("d   = e^-1 mod phi =", d)
    print("check e*d mod phi  =", (e * d) % phi)

    # n is small, so encrypt one character at a time
    cipher = [pow(ord(ch), e, n) for ch in MESSAGE]
    print("\nciphertext (per character):", cipher[:6], "...")
    plain = "".join(chr(pow(c, d, n)) for c in cipher)
    print("decrypted                 :", plain)
    return plain == MESSAGE


if __name__ == "__main__":
    print("message:", MESSAGE)
    print("\n=========== A) LIBRARY RSA (2048-bit, OAEP) ===========")
    ok1 = library_rsa()
    print("\n=========== B) RAW RSA MATHS (own primes) ============")
    ok2 = manual_rsa()
    print("\nboth round trips correct:", ok1 and ok2)
