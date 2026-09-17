"""
LAB 1 - ADDITIONAL 3
Vigenere cipher with keyword "HEALTH".
Message: "Life is full of surprises"

CONCEPT: same as exercise 2a - the keyword repeats over the message,
each letter getting its own shift.
"""

MSG = "Life is full of surprises"
KEY = "HEALTH"


def clean(t):
    return "".join(c for c in t.upper() if c.isalpha())


def vigenere(text, keyword, encrypt=True):
    t, k = clean(text), clean(keyword)
    sign = 1 if encrypt else -1
    return "".join(
        chr(((ord(t[i]) - 65) + sign * (ord(k[i % len(k)]) - 65)) % 26 + 65)
        for i in range(len(t)))


if __name__ == "__main__":
    print("plaintext :", clean(MSG))
    print("keyword   :", KEY, "-> repeated:",
          "".join(KEY[i % len(KEY)] for i in range(len(clean(MSG)))))
    ct = vigenere(MSG, KEY, True)
    print("cipher    :", ct)
    print("decrypted :", vigenere(ct, KEY, False))

    print("\nletter by letter:")
    t, k = clean(MSG), clean(KEY)
    for i in range(len(t)):
        ki = k[i % len(k)]
        print(f"   {t[i]}({ord(t[i])-65:2d}) + {ki}({ord(ki)-65:2d}) "
              f"= {ct[i]}({ord(ct[i])-65:2d})")
