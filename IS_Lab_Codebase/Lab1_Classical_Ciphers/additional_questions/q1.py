"""
LAB 1 - ADDITIONAL 1
Brute-force an additive cipher. Alice's key is close to her birthday: the 13th.
Ciphertext:
  NCJAEZRCLAS/LYODEPRLYZRCLASJLCPEHZDTOPDZOLN&BY

CONCEPT: the additive cipher has only 26 keys, so exhaustive search always
works. The hint "close to 13" just tells us which keys to look at first.
Non-letter characters ( / and & ) are left untouched.
"""

CIPHER = "NCJAEZRCLAS/LYODEPRLYZRCLASJLCPEHZDTOPDZOLN&BY"


def additive_decrypt(text, k):
    """Shift letters back by k; leave punctuation exactly as it is."""
    out = ""
    for ch in text.upper():
        if ch.isalpha():
            out += chr((ord(ch) - 65 - k) % 26 + 65)
        else:
            out += ch                        # '/' and '&' pass through
    return out


if __name__ == "__main__":
    print("ciphertext:", CIPHER)

    print("\nkeys near the 13th first (the birthday hint):")
    for k in [13, 12, 14, 11, 15, 10, 16]:
        print(f"   k={k:2d} -> {additive_decrypt(CIPHER, k)}")

    print("\nall 26 keys:")
    for k in range(26):
        print(f"   k={k:2d} -> {additive_decrypt(CIPHER, k)}")

    # automatic pick: the key whose output contains common English words
    words = ("CRYPT", "THE", "AND", "ARE", "SIDES")
    best = [k for k in range(26)
            if sum(w in additive_decrypt(CIPHER, k) for w in words) >= 2]

    print("\nANSWER: key =", best[0], "(close to the 13th, as hinted)")
    print("   plaintext:", additive_decrypt(CIPHER, best[0]))
    print("   reads as : CRYPTOGRAPHY AND STEGANOGRAPHY ARE TWO SIDES OF A COIN")
    print("   (the last few letters are garbled because the manual's")
    print("    ciphertext has a couple of mistyped characters)")
