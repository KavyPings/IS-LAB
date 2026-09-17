"""
LAB 1 - EXERCISE 4
Hill cipher. Message: "We live in an insecure world"
Key matrix K = [[3, 3],
                [2, 7]]

CONCEPT: block cipher using linear algebra mod 26.
  Encrypt: C = K * P  (mod 26)   - P is a column of n letters
  Decrypt: P = K^-1 * C (mod 26) - needs the matrix inverse mod 26,
           which exists only when gcd(det(K), 26) == 1.
"""

KEY = [[3, 3],
       [2, 7]]
MSG = "We live in an insecure world"


def clean(t):
    return "".join(c for c in t.upper() if c.isalpha())


def mod_inverse(a, m=26):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None


def encrypt_blocks(text, key):
    """Multiply every block of n letters by the key matrix."""
    n = len(key)
    p = [ord(c) - 65 for c in clean(text)]
    while len(p) % n:
        p.append(23)                       # pad with 'X' (23) to fill a block
    out = []
    for i in range(0, len(p), n):
        block = p[i:i + n]
        for row in key:                    # each output letter = row . block
            out.append(sum(row[j] * block[j] for j in range(n)) % 26)
    return "".join(chr(x + 65) for x in out)


def inverse_2x2(m):
    """K^-1 = det^-1 * [[d, -b], [-c, a]]  (mod 26)"""
    det = (m[0][0] * m[1][1] - m[0][1] * m[1][0]) % 26
    det_inv = mod_inverse(det)
    if det_inv is None:
        raise ValueError(f"det={det} has no inverse mod 26 -> key unusable")
    return [[(m[1][1] * det_inv) % 26, (-m[0][1] * det_inv) % 26],
            [(-m[1][0] * det_inv) % 26, (m[0][0] * det_inv) % 26]]


if __name__ == "__main__":
    det = (KEY[0][0] * KEY[1][1] - KEY[0][1] * KEY[1][0]) % 26
    print("key       :", KEY)
    print("det(K)    :", det, " inverse of det mod 26 =", mod_inverse(det))

    print("plaintext :", clean(MSG))
    ct = encrypt_blocks(MSG, KEY)
    print("cipher    :", ct)

    inv = inverse_2x2(KEY)
    print("K^-1      :", inv)
    print("decrypted :", encrypt_blocks(ct, inv))   # same routine, inverse key
