"""
CONCEPT 01 : CLASSICAL / CLASSICAL SUBSTITUTION + TRANSPOSITION CIPHERS
(Lab 1 - Basic Symmetric Key Ciphers)

Pure python, NO library needed.
Every function is standalone -> copy-paste any one of them into an exam answer.

Common helpers first, then one encrypt/decrypt pair per cipher.
"""

# ---------------------------------------------------------------------------
# HELPERS (needed by almost every classical cipher)
# ---------------------------------------------------------------------------

def clean(text):
    """Keep only A-Z letters, uppercase them, drop spaces/punctuation.
    Manual always says 'ignore the space between words' -> use this first."""
    return "".join(ch for ch in text.upper() if ch.isalpha())


def to_nums(text):
    """'ABC' -> [0,1,2]   (A=0 ... Z=25)"""
    return [ord(ch) - 65 for ch in text]


def to_text(nums):
    """[0,1,2] -> 'ABC'"""
    return "".join(chr(n % 26 + 65) for n in nums)


def mod_inverse(a, m):
    """Find x such that (a*x) % m == 1.  Needed for multiplicative/affine/Hill.
    Brute force over 0..m-1 is fine because m is small (26)."""
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None                      # no inverse => gcd(a,m) != 1


def egcd(a, b):
    """Extended Euclid: returns (g, x, y) with a*x + b*y = g = gcd(a,b).
    Use this instead of mod_inverse when numbers are big (RSA etc.)."""
    if b == 0:
        return (a, 1, 0)
    g, x, y = egcd(b, a % b)
    return (g, y, x - (a // b) * y)


# ---------------------------------------------------------------------------
# 1. ADDITIVE / CAESAR / SHIFT CIPHER      C = (P + k) mod 26
# ---------------------------------------------------------------------------

def additive_encrypt(plaintext, key):
    return to_text([(p + key) % 26 for p in to_nums(clean(plaintext))])


def additive_decrypt(ciphertext, key):
    return to_text([(c - key) % 26 for c in to_nums(clean(ciphertext))])


# ---------------------------------------------------------------------------
# 2. MULTIPLICATIVE CIPHER                 C = (P * k) mod 26
#    key must be coprime with 26 (1,3,5,7,9,11,15,17,19,21,23,25)
# ---------------------------------------------------------------------------

def multiplicative_encrypt(plaintext, key):
    return to_text([(p * key) % 26 for p in to_nums(clean(plaintext))])


def multiplicative_decrypt(ciphertext, key):
    k_inv = mod_inverse(key, 26)          # need inverse of key to undo multiply
    return to_text([(c * k_inv) % 26 for c in to_nums(clean(ciphertext))])


# ---------------------------------------------------------------------------
# 3. AFFINE CIPHER                         C = (a*P + b) mod 26
#    key = (a, b); a must be coprime with 26
# ---------------------------------------------------------------------------

def affine_encrypt(plaintext, a, b):
    return to_text([(a * p + b) % 26 for p in to_nums(clean(plaintext))])


def affine_decrypt(ciphertext, a, b):
    a_inv = mod_inverse(a, 26)
    return to_text([(a_inv * (c - b)) % 26 for c in to_nums(clean(ciphertext))])


# ---------------------------------------------------------------------------
# 4. VIGENERE CIPHER (polyalphabetic)      C_i = (P_i + K_i) mod 26
#    key is a word, repeated over the message
# ---------------------------------------------------------------------------

def vigenere_encrypt(plaintext, keyword):
    p = to_nums(clean(plaintext))
    k = to_nums(clean(keyword))
    # k[i % len(k)] -> repeat the keyword cyclically
    return to_text([(p[i] + k[i % len(k)]) % 26 for i in range(len(p))])


def vigenere_decrypt(ciphertext, keyword):
    c = to_nums(clean(ciphertext))
    k = to_nums(clean(keyword))
    return to_text([(c[i] - k[i % len(k)]) % 26 for i in range(len(c))])


# ---------------------------------------------------------------------------
# 5. AUTOKEY CIPHER
#    keystream = [numeric key] + plaintext itself (the plaintext becomes the key)
# ---------------------------------------------------------------------------

def autokey_encrypt(plaintext, key):
    """key is a NUMBER (e.g. 7). Manual's Lab-1 Q2b uses key = 7."""
    p = to_nums(clean(plaintext))
    stream = [key] + p[:-1]               # first key, then plaintext shifted by 1
    return to_text([(p[i] + stream[i]) % 26 for i in range(len(p))])


def autokey_decrypt(ciphertext, key):
    c = to_nums(clean(ciphertext))
    p = []
    prev = key                            # first keystream value is the key
    for ch in c:
        val = (ch - prev) % 26
        p.append(val)
        prev = val                        # recovered letter becomes next key
    return to_text(p)


def autokey_word_encrypt(plaintext, keyword):
    """Variant where the key is a WORD instead of a number."""
    p = to_nums(clean(plaintext))
    stream = to_nums(clean(keyword)) + p
    return to_text([(p[i] + stream[i]) % 26 for i in range(len(p))])


def autokey_word_decrypt(ciphertext, keyword):
    c = to_nums(clean(ciphertext))
    stream = to_nums(clean(keyword))
    p = []
    for i in range(len(c)):
        val = (c[i] - stream[i]) % 26
        p.append(val)
        stream.append(val)                # extend keystream with recovered letter
    return to_text(p)


# ---------------------------------------------------------------------------
# 6. PLAYFAIR CIPHER  (5x5 matrix, digraph substitution, I/J share a cell)
# ---------------------------------------------------------------------------

def playfair_matrix(key):
    """Build the 5x5 key square: key letters first, then remaining alphabet."""
    key = clean(key).replace("J", "I")
    seen = []
    for ch in key + "ABCDEFGHIKLMNOPQRSTUVWXYZ":   # note: no 'J'
        if ch not in seen:
            seen.append(ch)
    return [seen[i * 5:(i + 1) * 5] for i in range(5)]


def _pf_pos(matrix, ch):
    """Return (row, col) of a letter in the 5x5 matrix."""
    for r in range(5):
        for c in range(5):
            if matrix[r][c] == ch:
                return r, c


def playfair_pairs(text):
    """Split into 2-letter groups; insert 'X' between doubles; pad last with 'X'."""
    text = clean(text).replace("J", "I")
    pairs, i = [], 0
    while i < len(text):
        a = text[i]
        b = text[i + 1] if i + 1 < len(text) else "X"
        if a == b:                       # same letter twice -> separate with X
            pairs.append(a + "X")
            i += 1
        else:
            pairs.append(a + b)
            i += 2
    return pairs


def playfair_encrypt(plaintext, key):
    m = playfair_matrix(key)
    out = ""
    for a, b in playfair_pairs(plaintext):
        r1, c1 = _pf_pos(m, a)
        r2, c2 = _pf_pos(m, b)
        if r1 == r2:                     # same row -> shift RIGHT
            out += m[r1][(c1 + 1) % 5] + m[r2][(c2 + 1) % 5]
        elif c1 == c2:                   # same column -> shift DOWN
            out += m[(r1 + 1) % 5][c1] + m[(r2 + 1) % 5][c2]
        else:                            # rectangle -> swap columns
            out += m[r1][c2] + m[r2][c1]
    return out


def playfair_decrypt(ciphertext, key):
    m = playfair_matrix(key)
    text = clean(ciphertext)
    out = ""
    for i in range(0, len(text), 2):
        a, b = text[i], text[i + 1]
        r1, c1 = _pf_pos(m, a)
        r2, c2 = _pf_pos(m, b)
        if r1 == r2:                     # same row -> shift LEFT
            out += m[r1][(c1 - 1) % 5] + m[r2][(c2 - 1) % 5]
        elif c1 == c2:                   # same column -> shift UP
            out += m[(r1 - 1) % 5][c1] + m[(r2 - 1) % 5][c2]
        else:
            out += m[r1][c2] + m[r2][c1]
    return out


# ---------------------------------------------------------------------------
# 7. HILL CIPHER  (matrix multiplication mod 26)
#    C = K * P mod 26 , works on blocks of size n (n = matrix size)
# ---------------------------------------------------------------------------

def hill_encrypt(plaintext, key_matrix):
    n = len(key_matrix)
    p = to_nums(clean(plaintext))
    while len(p) % n:                     # pad with 'X' so length divides by n
        p.append(23)
    out = []
    for i in range(0, len(p), n):
        block = p[i:i + n]
        for row in key_matrix:            # row . block  (dot product) mod 26
            out.append(sum(row[j] * block[j] for j in range(n)) % 26)
    return to_text(out)


def matrix_mod_inverse(m, mod=26):
    """Inverse of a 2x2 or 3x3 matrix mod 26 (adjugate / determinant method)."""
    n = len(m)
    if n == 2:
        det = (m[0][0] * m[1][1] - m[0][1] * m[1][0]) % mod
        det_inv = mod_inverse(det, mod)
        if det_inv is None:
            raise ValueError("key matrix not invertible mod 26")
        return [[(m[1][1] * det_inv) % mod, (-m[0][1] * det_inv) % mod],
                [(-m[1][0] * det_inv) % mod, (m[0][0] * det_inv) % mod]]
    # 3x3 via cofactor matrix
    def minor(mat, i, j):
        return [row[:j] + row[j + 1:] for k, row in enumerate(mat) if k != i]
    def det2(x):
        return x[0][0] * x[1][1] - x[0][1] * x[1][0]
    det = sum((-1) ** j * m[0][j] * det2(minor(m, 0, j)) for j in range(3)) % mod
    det_inv = mod_inverse(det, mod)
    if det_inv is None:
        raise ValueError("key matrix not invertible mod 26")
    adj = [[((-1) ** (i + j) * det2(minor(m, j, i))) % mod for j in range(3)]
           for i in range(3)]
    return [[(adj[i][j] * det_inv) % mod for j in range(3)] for i in range(3)]


def hill_decrypt(ciphertext, key_matrix):
    inv = matrix_mod_inverse(key_matrix)  # decryption key = K^-1 mod 26
    return hill_encrypt(ciphertext, inv)  # same maths, inverse key


# ---------------------------------------------------------------------------
# 8. TRANSPOSITION CIPHERS
# ---------------------------------------------------------------------------

def keyed_transposition_encrypt(plaintext, perm):
    """perm = tuple like (2,0,1) meaning: out[0]=in[2], out[1]=in[0], out[2]=in[1].
    Text is cut into blocks of len(perm) and each block is permuted."""
    t = clean(plaintext)
    n = len(perm)
    while len(t) % n:
        t += "X"
    out = ""
    for i in range(0, len(t), n):
        block = t[i:i + n]
        out += "".join(block[p] for p in perm)
    return out


def keyed_transposition_decrypt(ciphertext, perm):
    n = len(perm)
    inv = [0] * n
    for i, p in enumerate(perm):          # build the inverse permutation
        inv[p] = i
    out = ""
    for i in range(0, len(ciphertext), n):
        block = ciphertext[i:i + n]
        out += "".join(block[p] for p in inv)
    return out


def rail_fence_encrypt(plaintext, rails):
    """Keyless zig-zag transposition."""
    t = clean(plaintext)
    rows = [""] * rails
    r, step = 0, 1
    for ch in t:
        rows[r] += ch
        if r == 0:
            step = 1
        elif r == rails - 1:
            step = -1
        r += step
    return "".join(rows)


def rail_fence_decrypt(ciphertext, rails):
    n = len(ciphertext)
    pattern, r, step = [], 0, 1
    for _ in range(n):                    # first work out which rail each char is on
        pattern.append(r)
        if r == 0:
            step = 1
        elif r == rails - 1:
            step = -1
        r += step
    out = [""] * n
    idx = 0
    for rail in range(rails):
        for i in range(n):
            if pattern[i] == rail:
                out[i] = ciphertext[idx]
                idx += 1
    return "".join(out)


# ---------------------------------------------------------------------------
# 9. ATTACKS (brute force / known-plaintext)
# ---------------------------------------------------------------------------

def brute_force_additive(ciphertext, show_all=True):
    """Try all 26 keys. Returns list of (key, plaintext)."""
    results = []
    for k in range(26):
        pt = additive_decrypt(ciphertext, k)
        results.append((k, pt))
        if show_all:
            print(f"key={k:2d} -> {pt}")
    return results


def brute_force_affine(ciphertext, contains=None):
    """Try all valid (a,b) affine keys. If `contains` given, only print hits."""
    valid_a = [a for a in range(1, 26) if mod_inverse(a, 26) is not None]
    hits = []
    for a in valid_a:
        for b in range(26):
            pt = affine_decrypt(ciphertext, a, b)
            if contains is None or contains.upper() in pt:
                hits.append((a, b, pt))
    return hits


def affine_key_from_known_pair(p1, c1, p2, c2):
    """Known-plaintext attack on affine: solve  c = a*p + b  for two pairs.
    p1,c1,p2,c2 are single letters, e.g. ('a','G','b','L')."""
    p1, c1, p2, c2 = (to_nums(clean(x))[0] for x in (p1, c1, p2, c2))
    # c1 - c2 = a*(p1 - p2)  ->  a = (c1-c2) * inv(p1-p2)
    a = ((c1 - c2) * mod_inverse((p1 - p2) % 26, 26)) % 26
    b = (c1 - a * p1) % 26
    return a, b


def shift_key_from_known_pair(plain_char, cipher_char):
    """Known-plaintext attack on shift cipher: k = C - P mod 26."""
    return (to_nums(clean(cipher_char))[0] - to_nums(clean(plain_char))[0]) % 26


def find_transposition_key(plaintext, ciphertext, block_size):
    """Chosen-plaintext attack: recover the permutation used, for a given block size.
    Returns perm tuple, or None if this block size is not consistent."""
    p, c = clean(plaintext), clean(ciphertext)
    if len(p) != len(c) or len(p) % block_size:
        return None
    perm = []
    for j in range(block_size):           # which input position produced output j?
        found = None
        for i in range(block_size):
            if all(c[b + j] == p[b + i]
                   for b in range(0, len(p), block_size)):
                found = i
                break
        if found is None:
            return None
        perm.append(found)
    return tuple(perm)


# ---------------------------------------------------------------------------
# quick self-test when run directly
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    msg = "I am learning information security"
    print("additive   :", additive_encrypt(msg, 20), "->", additive_decrypt(additive_encrypt(msg, 20), 20))
    print("affine     :", affine_encrypt(msg, 15, 20), "->", affine_decrypt(affine_encrypt(msg, 15, 20), 15, 20))
    print("vigenere   :", vigenere_encrypt("the house is being sold tonight", "dollars"))
    print("playfair   :", playfair_encrypt("The key is hidden under the door pad", "GUIDANCE"))
    print("hill       :", hill_encrypt("We live in an insecure world", [[3, 3], [2, 7]]))
    print("hill dec   :", hill_decrypt(hill_encrypt("We live in an insecure world", [[3, 3], [2, 7]]), [[3, 3], [2, 7]]))
