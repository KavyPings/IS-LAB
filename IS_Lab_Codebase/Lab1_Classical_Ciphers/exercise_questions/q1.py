"""
LAB 1 - EXERCISE 1
Encrypt "I am learning information security" (ignore spaces), then decrypt:
  a) Additive cipher,       key = 20
  b) Multiplicative cipher, key = 15
  c) Affine cipher,         key = (15, 20)

CONCEPT: monoalphabetic substitution over Z26.
  additive       C = (P + k)      mod 26
  multiplicative C = (P * k)      mod 26
  affine         C = (a*P + b)    mod 26
Decryption needs the modular inverse of the multiplier.
"""

MSG = "I am learning information security"


def clean(text):
    """Drop spaces/punctuation, uppercase. 'ignore the space between words'."""
    return "".join(c for c in text.upper() if c.isalpha())


def mod_inverse(a, m=26):
    """Smallest x with (a*x) % m == 1. Exists only if gcd(a, m) == 1."""
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None


# --- a) ADDITIVE -----------------------------------------------------------
def additive_encrypt(text, k):
    return "".join(chr((ord(c) - 65 + k) % 26 + 65) for c in clean(text))


def additive_decrypt(text, k):
    return "".join(chr((ord(c) - 65 - k) % 26 + 65) for c in clean(text))


# --- b) MULTIPLICATIVE -----------------------------------------------------
def multiplicative_encrypt(text, k):
    return "".join(chr(((ord(c) - 65) * k) % 26 + 65) for c in clean(text))


def multiplicative_decrypt(text, k):
    k_inv = mod_inverse(k)                 # undo multiply with the inverse
    return "".join(chr(((ord(c) - 65) * k_inv) % 26 + 65) for c in clean(text))


# --- c) AFFINE -------------------------------------------------------------
def affine_encrypt(text, a, b):
    return "".join(chr(((ord(c) - 65) * a + b) % 26 + 65) for c in clean(text))


def affine_decrypt(text, a, b):
    a_inv = mod_inverse(a)                 # P = a^-1 * (C - b) mod 26
    return "".join(chr((a_inv * (ord(c) - 65 - b)) % 26 + 65) for c in clean(text))


if __name__ == "__main__":
    print("plaintext        :", clean(MSG))

    ct = additive_encrypt(MSG, 20)
    print("\na) additive k=20")
    print("   cipher        :", ct)
    print("   decrypted     :", additive_decrypt(ct, 20))

    ct = multiplicative_encrypt(MSG, 15)
    print("\nb) multiplicative k=15   (inverse of 15 mod 26 =", mod_inverse(15), ")")
    print("   cipher        :", ct)
    print("   decrypted     :", multiplicative_decrypt(ct, 15))

    ct = affine_encrypt(MSG, 15, 20)
    print("\nc) affine (a=15, b=20)")
    print("   cipher        :", ct)
    print("   decrypted     :", affine_decrypt(ct, 15, 20))
