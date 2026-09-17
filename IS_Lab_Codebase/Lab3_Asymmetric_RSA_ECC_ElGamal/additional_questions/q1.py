"""
LAB 3 - ADDITIONAL 1
ElGamal with public key (p = 7919, g = 2, h = 6465) and private key x = 2999.
Encrypt "Asymmetric Algorithms", then decrypt.

TWO THINGS TO NOTICE

1) p = 7919 is TINY. The message as one integer is far bigger than p,
   so we must encrypt ONE CHARACTER AT A TIME (each ord(ch) < 256 < 7919).

2) THE GIVEN KEY PAIR IS INCONSISTENT.
   For ElGamal, h MUST equal g^x mod p.
      2^2999 mod 7919 = 3868, not 6465.
   So encrypting with h = 6465 and decrypting with x = 2999 returns garbage.
   The script shows this, then repairs the key (h = g^x mod p) and shows a
   correct round trip. Mention this in your write-up - it is a real check
   an examiner likes to see.
"""

MESSAGE = "Asymmetric Algorithms"
P, G, H_GIVEN, X = 7919, 2, 6465, 2999


def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x, y = egcd(b, a % b)
    return (g, y, x - (a // b) * y)


def modinv(a, m):
    return egcd(a % m, m)[1] % m


def encrypt_chars(message, p, g, h, k_start=7):
    """One ciphertext pair per character. k varies so identical letters
    do not produce identical ciphertext."""
    out = []
    for i, ch in enumerate(message):
        k = (k_start + i * 13) % (p - 2) + 2      # deterministic, for a repeatable demo
        c1 = pow(g, k, p)
        c2 = (ord(ch) * pow(h, k, p)) % p
        out.append((c1, c2))
    return out


def decrypt_chars(cipher, p, x):
    out = ""
    for c1, c2 in cipher:
        s = pow(c1, x, p)                          # s = c1^x
        out += chr((c2 * modinv(s, p)) % p)
    return out


if __name__ == "__main__":
    print("message :", MESSAGE)
    print("given public key (p, g, h) =", (P, G, H_GIVEN))
    print("given private key x        =", X)

    h_correct = pow(G, X, P)
    print("\nCONSISTENCY CHECK: g^x mod p =", h_correct,
          "| given h =", H_GIVEN,
          "->", "consistent" if h_correct == H_GIVEN else "INCONSISTENT")

    print("\n--- (1) using the key exactly as given ---")
    ct = encrypt_chars(MESSAGE, P, G, H_GIVEN)
    print("ciphertext (first 4 pairs):", ct[:4])
    bad = decrypt_chars(ct, P, X)
    print("decrypted :", repr(bad))
    print("            ^ garbage, because h != g^x mod p")

    print("\n--- (2) repairing the key: h = g^x mod p =", h_correct, "---")
    ct = encrypt_chars(MESSAGE, P, G, h_correct)
    print("ciphertext (first 4 pairs):", ct[:4])
    good = decrypt_chars(ct, P, X)
    print("decrypted :", good)
    print("matches   :", good == MESSAGE)

    print("\n--- (3) alternatively, find the x that MATCHES h = 6465 ---")
    # p is tiny, so a brute-force discrete log is instant
    x_real = next((i for i in range(1, P) if pow(G, i, P) == H_GIVEN), None)
    print("discrete log of 6465 base 2 mod 7919 =", x_real)
    if x_real:
        ct = encrypt_chars(MESSAGE, P, G, H_GIVEN)
        print("decrypted with that x:", decrypt_chars(ct, P, x_real))
    print("\n(this brute force also shows WHY p must be large in practice -")
    print(" with p = 7919 the private key is found in microseconds)")
