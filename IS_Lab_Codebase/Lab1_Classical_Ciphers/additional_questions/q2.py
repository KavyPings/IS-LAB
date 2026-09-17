"""
LAB 1 - ADDITIONAL 2
Eve types "abcdefghi" into Alice's machine and sees "CABDEHFGL".
Alice is using a KEYED TRANSPOSITION cipher.
  a) What type of attack is Eve launching?
  b) What is the size of the permutation key?

ANSWERS
  a) CHOSEN-PLAINTEXT attack.
     Eve picked the plaintext herself and observed the ciphertext.
     (Known-plaintext = she is merely given a pair; chosen = she selects it.)

  b) A transposition cipher only MOVES letters, it never changes them.
     So the block size is found by cutting the text into blocks of size n
     and checking that each ciphertext block is a rearrangement of the
     matching plaintext block. Here n = 3.
        abc -> CAB   (positions 2,0,1)
        def -> DEH   <- 'H' is not in 'def', so the manual's string has a
                        typo; with a consistent example the method works.
     The code below finds the key automatically for any n.
"""


def clean(t):
    return "".join(c for c in t.upper() if c.isalpha())


def possible_block_sizes(plain, cipher):
    """A block size is possible only if every block is an anagram."""
    p, c = clean(plain), clean(cipher)
    if len(p) != len(c):
        return []
    sizes = []
    for n in range(2, len(p) + 1):
        if len(p) % n:
            continue
        if all(sorted(p[i:i + n]) == sorted(c[i:i + n])
               for i in range(0, len(p), n)):
            sizes.append(n)
    return sizes


def find_permutation(plain, cipher, n):
    """perm[j] = which input position ended up at output position j."""
    p, c = clean(plain), clean(cipher)
    perm = []
    for j in range(n):
        for i in range(n):
            if all(c[b + j] == p[b + i] for b in range(0, len(p), n)):
                perm.append(i)
                break
        else:
            return None                     # inconsistent -> wrong block size
    return tuple(perm)


def transpose(text, perm):
    n = len(perm)
    t = clean(text)
    while len(t) % n:
        t += "X"
    return "".join("".join(t[i:i + n][k] for k in perm)
                   for i in range(0, len(t), n))


def inverse_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return tuple(inv)


if __name__ == "__main__":
    print("a) Attack type : CHOSEN-PLAINTEXT attack")
    print("   (Eve chose 'abcdefghi' herself and read off the ciphertext)\n")

    P, C = "abcdefghi", "CABDEHFGL"
    print(f"   manual data  : {P} -> {C}")
    print("   block sizes that work:", possible_block_sizes(P, C) or
          "NONE - the manual's ciphertext is not an anagram of the plaintext"
          " (it contains 'L' and 'H', which are not in 'abcdefghi')")

    print("\nb) Same method on a CONSISTENT example, key size 3, perm (2,0,1):")
    P2 = "abcdefghi"
    C2 = transpose(P2, (2, 0, 1))
    print(f"   {P2} -> {C2}")
    print("   possible block sizes :", possible_block_sizes(P2, C2))
    for n in possible_block_sizes(P2, C2):
        print(f"   n={n} -> permutation {find_permutation(P2, C2, n)}")

    perm = find_permutation(P2, C2, 3)
    print(f"\n   recovered key : {perm}  (size = {len(perm)})")
    print("   inverse key   :", inverse_perm(perm))
    print("   decrypt check :", transpose(C2, inverse_perm(perm)))
