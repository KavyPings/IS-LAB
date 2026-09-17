"""
LAB 1 - EXERCISE 2
Encrypt "the house is being sold tonight" (ignore spaces), then decrypt:
  a) Vigenere cipher, key = "dollars"
  b) Autokey cipher,  key = 7

CONCEPT: polyalphabetic substitution - the shift CHANGES for each letter.
  Vigenere : keystream = keyword repeated over and over
  Autokey  : keystream = the key, then the PLAINTEXT itself
             (so the key never repeats -> harder to break with Kasiski)
"""

MSG = "the house is being sold tonight"


def clean(t):
    return "".join(c for c in t.upper() if c.isalpha())


def nums(t):
    return [ord(c) - 65 for c in t]


def text(n):
    return "".join(chr(x % 26 + 65) for x in n)


# --- a) VIGENERE -----------------------------------------------------------
def vigenere_encrypt(msg, keyword):
    p, k = nums(clean(msg)), nums(clean(keyword))
    # k[i % len(k)] makes the keyword repeat: d o l l a r s d o l l a r s ...
    return text([(p[i] + k[i % len(k)]) % 26 for i in range(len(p))])


def vigenere_decrypt(ct, keyword):
    c, k = nums(clean(ct)), nums(clean(keyword))
    return text([(c[i] - k[i % len(k)]) % 26 for i in range(len(c))])


# --- b) AUTOKEY (numeric key) ---------------------------------------------
def autokey_encrypt(msg, key):
    p = nums(clean(msg))
    stream = [key] + p[:-1]                # key, then plaintext shifted by one
    return text([(p[i] + stream[i]) % 26 for i in range(len(p))])


def autokey_decrypt(ct, key):
    c = nums(clean(ct))
    out, prev = [], key                    # prev = current keystream value
    for x in c:
        v = (x - prev) % 26
        out.append(v)
        prev = v                           # the letter we just recovered
    return text(out)


if __name__ == "__main__":
    print("plaintext :", clean(MSG))

    ct = vigenere_encrypt(MSG, "dollars")
    print("\na) Vigenere key='dollars'")
    print("   cipher :", ct)
    print("   plain  :", vigenere_decrypt(ct, "dollars"))

    ct = autokey_encrypt(MSG, 7)
    print("\nb) Autokey key=7")
    print("   cipher :", ct)
    print("   plain  :", autokey_decrypt(ct, 7))
