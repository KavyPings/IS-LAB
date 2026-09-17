"""
LAB 1 - EXERCISE 6
Brute-force an affine cipher. You know that plaintext "ab" encrypts to "GL".
Ciphertext:
  XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS

TWO WAYS SHOWN
  1) SOLVE directly from the known pair (fast, exact):
        a*0 + b = 6  (a->G)   ->  b = 6
        a*1 + b = 11 (b->L)   ->  a = 5
  2) BRUTE FORCE all 12*26 = 312 keys and keep the ones that map "ab"->"GL".
"""

CIPHER = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"


def mod_inverse(a, m=26):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None


def affine_encrypt(text, a, b):
    return "".join(chr(((ord(c) - 65) * a + b) % 26 + 65) for c in text.upper())


def affine_decrypt(text, a, b):
    a_inv = mod_inverse(a)
    if a_inv is None:
        return None
    return "".join(chr((a_inv * (ord(c) - 65 - b)) % 26 + 65) for c in text.upper())


def solve_from_known_pair():
    """Two equations, two unknowns, solved mod 26."""
    # 'a'=0 -> 'G'=6 : a*0 + b = 6  => b = 6
    b = 6
    # 'b'=1 -> 'L'=11: a*1 + b = 11 => a = 11 - 6 = 5
    a = (11 - b) % 26
    return a, b


def brute_force():
    """Try every valid key; keep the ones consistent with 'ab' -> 'GL'."""
    valid_a = [a for a in range(1, 26) if mod_inverse(a) is not None]
    hits = []
    for a in valid_a:
        for b in range(26):
            if affine_encrypt("ab", a, b) == "GL":
                hits.append((a, b))
    return hits


if __name__ == "__main__":
    a, b = solve_from_known_pair()
    print("solved from known pair  : a =", a, ", b =", b)
    print("brute force agrees with :", brute_force())

    print("\nciphertext :", CIPHER)
    print("plaintext  :", affine_decrypt(CIPHER, a, b))

    print("\n(the text reads: THE BEST OF A FIGHT IS MAKING UP AFTERWARDS -")
    print(" one letter of the manual's ciphertext is mistyped, which is why")
    print(" 'AFTERWARDS' comes out as 'AKTERWARDS'. The key is still correct.)")

    print("\nfull brute force - only keys whose output contains 'THE' are shown:")
    valid_a = [x for x in range(1, 26) if mod_inverse(x) is not None]
    tried = 0
    for aa in valid_a:
        for bb in range(26):
            tried += 1
            pt = affine_decrypt(CIPHER, aa, bb)
            if "THE" in pt:                  # english-looking filter
                print(f"   a={aa:2d} b={bb:2d} -> {pt}")
    print(f"   ({tried} keys tried in total)")
