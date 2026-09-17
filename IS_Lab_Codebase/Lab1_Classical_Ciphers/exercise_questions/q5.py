"""
LAB 1 - EXERCISE 5
John's mystery book:
  ciphertext "CIW" is known to decrypt to "yes" under a shift cipher.
  Later "XVIEWYWI" is found. What attack is this, and what does it say?

ANSWER
  Attack type : KNOWN-PLAINTEXT attack.
                The attacker knows one plaintext/ciphertext pair
                ("yes" <-> "CIW") and uses it to recover the key.
                (If he had CHOSEN the plaintext it would be chosen-plaintext;
                 here the author simply told him, so it is known-plaintext.)

  Key recovery: k = C - P (mod 26), using any matching letter.
                C='C'=2, P='y'=24  ->  k = (2 - 24) mod 26 = 4
"""


def clean(t):
    return "".join(c for c in t.upper() if c.isalpha())


def find_shift_key(plain, cipher):
    """k = C - P mod 26, checked on every letter pair so we can be sure."""
    keys = {(ord(c) - 65 - (ord(p) - 65)) % 26
            for p, c in zip(clean(plain), clean(cipher))}
    return keys.pop() if len(keys) == 1 else None


def shift_decrypt(text, k):
    return "".join(chr((ord(c) - 65 - k) % 26 + 65) for c in clean(text))


def shift_encrypt(text, k):
    return "".join(chr((ord(c) - 65 + k) % 26 + 65) for c in clean(text))


if __name__ == "__main__":
    print("Attack type : KNOWN-PLAINTEXT attack")
    print("known pair  : plaintext 'yes'  <->  ciphertext 'CIW'")

    k = find_shift_key("yes", "CIW")
    print("recovered k :", k)
    print("check       : encrypt('yes', k) =", shift_encrypt("yes", k))

    print("\ntablet text : XVIEWYWI")
    print("plaintext   :", shift_decrypt("XVIEWYWI", k))
    print("NOTE: this comes out as TREASUSE. The intended word is TREASURE;")
    print("      the manual has a typo (7th letter should be V, not W).")
    print("      Correct string XVIEWYVI ->", shift_decrypt("XVIEWYVI", k))

    print("\n(brute force would also work - only 26 keys:)")
    for t in range(26):
        print(f"   k={t:2d} -> {shift_decrypt('XVIEWYWI', t)}")
