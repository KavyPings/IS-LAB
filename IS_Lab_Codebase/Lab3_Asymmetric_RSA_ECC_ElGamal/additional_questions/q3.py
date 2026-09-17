"""
LAB 3 - ADDITIONAL 3
Encrypt "Cryptographic Protocols" using RSA public key (n = 323, e = 5),
decrypt with private key (n = 323, d = 173).

CONCEPT: this is TEXTBOOK RSA with deliberately tiny numbers.
  n = 323 = 17 * 19,  phi = 16 * 18 = 288
  e = 5,  d = 173,    check: 5 * 173 = 865 = 3*288 + 1  -> e*d = 1 mod phi

Because n = 323 is smaller than 256*256, we can only encrypt ONE BYTE at a
time - and even then any character with ord >= 323 would break (none here,
ASCII is < 128).
"""

N, E, D = 323, 5, 173
MESSAGE = "Cryptographic Protocols"


def rsa_encrypt(message, n, e):
    """c = m^e mod n, per character."""
    return [pow(ord(ch), e, n) for ch in message]


def rsa_decrypt(cipher, n, d):
    """m = c^d mod n."""
    return "".join(chr(pow(c, d, n)) for c in cipher)


if __name__ == "__main__":
    print("public key  (n, e) =", (N, E))
    print("private key (n, d) =", (N, D))

    # verify the key pair is consistent
    p, q = 17, 19
    phi = (p - 1) * (q - 1)
    print(f"\nn = {p} * {q} = {p*q}")
    print(f"phi(n) = {p-1} * {q-1} = {phi}")
    print(f"e * d mod phi = {E} * {D} mod {phi} = {(E*D) % phi}  (must be 1)")

    print("\nmessage    :", MESSAGE)
    ct = rsa_encrypt(MESSAGE, N, E)
    print("ciphertext :", ct)
    pt = rsa_decrypt(ct, N, D)
    print("decrypted  :", pt)
    print("correct    :", pt == MESSAGE)

    print("\nper character trace (first 8):")
    for ch, c in list(zip(MESSAGE, ct))[:8]:
        print(f"   '{ch}' ord={ord(ch):3d}  -> {ord(ch)}^{E} mod {N} = {c:3d}"
              f"  -> {c}^{D} mod {N} = {pow(c, D, N)}")

    print("\nWHY THIS IS INSECURE")
    print("  n = 323 is factored instantly: 17 * 19.")
    print("  Anyone can then compute d and read everything.")
    print("  Also, encrypting per character makes it a simple substitution")
    print("  cipher - frequency analysis alone breaks it.")
    print("  Real RSA needs n of at least 2048 bits and OAEP padding.")
