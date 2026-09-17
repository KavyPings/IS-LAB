"""
LAB 1 - EXERCISE 3
Playfair cipher. Message: "The key is hidden under the door pad"
Key square built from the word "GUIDANCE", rest of the alphabet after it.

CONCEPT: digraph substitution on a 5x5 matrix.
  I and J share one cell (25 cells, 26 letters).
  Rules for each PAIR of letters:
    same row    -> take the letter to the RIGHT  (wrap around)
    same column -> take the letter BELOW         (wrap around)
    otherwise   -> rectangle: swap the columns
  Decryption is the same with LEFT / ABOVE.
"""

KEY = "GUIDANCE"
MSG = "The key is hidden under the door pad"


def clean(t):
    return "".join(c for c in t.upper() if c.isalpha()).replace("J", "I")


def build_matrix(key):
    """Key letters first (no repeats), then the rest of the alphabet."""
    seq = []
    for ch in clean(key) + "ABCDEFGHIKLMNOPQRSTUVWXYZ":     # note: no J
        if ch not in seq:
            seq.append(ch)
    return [seq[i * 5:(i + 1) * 5] for i in range(5)]


def find(matrix, ch):
    for r in range(5):
        for c in range(5):
            if matrix[r][c] == ch:
                return r, c


def make_pairs(text):
    """Split into digraphs. Double letters get an X between them."""
    t = clean(text)
    pairs, i = [], 0
    while i < len(t):
        a = t[i]
        b = t[i + 1] if i + 1 < len(t) else "X"        # pad odd length with X
        if a == b:
            pairs.append(a + "X")                      # break up the double
            i += 1
        else:
            pairs.append(a + b)
            i += 2
    return pairs


def playfair(text, key, encrypt=True):
    m = build_matrix(key)
    step = 1 if encrypt else -1                        # +1 encrypt, -1 decrypt
    pairs = make_pairs(text) if encrypt else \
        [clean(text)[i:i + 2] for i in range(0, len(clean(text)), 2)]
    out = ""
    for a, b in pairs:
        r1, c1 = find(m, a)
        r2, c2 = find(m, b)
        if r1 == r2:                                   # same row
            out += m[r1][(c1 + step) % 5] + m[r2][(c2 + step) % 5]
        elif c1 == c2:                                 # same column
            out += m[(r1 + step) % 5][c1] + m[(r2 + step) % 5][c2]
        else:                                          # rectangle
            out += m[r1][c2] + m[r2][c1]
    return out


if __name__ == "__main__":
    matrix = build_matrix(KEY)
    print("key matrix (key = GUIDANCE):")
    for row in matrix:
        print("   ", " ".join(row))

    print("\nplaintext :", clean(MSG))
    print("digraphs  :", " ".join(make_pairs(MSG)))
    ct = playfair(MSG, KEY, encrypt=True)
    print("cipher    :", ct)
    print("decrypted :", playfair(ct, KEY, encrypt=False))
    print("\n(note: X letters appear in the decryption - that is normal,")
    print(" they were inserted as padding/separators during encryption)")
