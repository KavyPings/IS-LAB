"""
=============================================================================
 CONCEPT 16 : THRESHOLD DECRYPTION AND SECRET SHARING   (Lab 7 / end-sem)
=============================================================================
"No single authority may be able to decrypt the result."

Two ways to split a secret:

  ADDITIVE  (k of k)  s = s1 + s2 + ... + sk. Every share is needed.
                      Cheap, and the shares can be used directly as exponents.
  SHAMIR    (t of n)  a random polynomial with the secret as its constant term.
                      Any t shares rebuild it; t-1 shares learn nothing.

Apply either one to the PRIVATE EXPONENT of a homomorphic scheme and you get
threshold decryption: the server aggregates the ciphertexts, and only a quorum
of authorities can turn the aggregate into a number.
=============================================================================
"""

import random

from Crypto.Util.number import getPrime


# ---------------------------------------------------------------------------
# SHAMIR t-of-n over a prime field
# ---------------------------------------------------------------------------

def shamir_prime_for(secret, margin=16):
    """The field has to be larger than the secret being split."""
    return getPrime(int(secret).bit_length() + margin)


def shamir_split(secret, t, n, prime):
    """f(x) = secret + a1*x + ... + a(t-1)*x^(t-1) mod prime; share i = (i, f(i))."""
    coeffs = [secret] + [random.randrange(1, prime) for _ in range(t - 1)]
    return [[i, sum(c * pow(i, j, prime) for j, c in enumerate(coeffs)) % prime]
            for i in range(1, n + 1)]


def shamir_combine(shares, prime):
    """Lagrange interpolation evaluated at x = 0."""
    total = 0
    for xi, yi in shares:
        num, den = 1, 1
        for xj, _ in shares:
            if xi != xj:
                num = (num * -xj) % prime
                den = (den * (xi - xj)) % prime
        total = (total + yi * num * pow(den, -1, prime)) % prime
    return total


# ---------------------------------------------------------------------------
# ADDITIVE k-of-k
# ---------------------------------------------------------------------------

def additive_split(secret, k):
    """s = s1 + ... + sk exactly, as integers. All k shares are required."""
    shares = [random.randrange(1, secret) for _ in range(k - 1)]
    shares.append(secret - sum(shares))
    return shares


def additive_combine(shares):
    return sum(shares)


# ---------------------------------------------------------------------------
# PUTTING IT ON A PAILLIER KEY
# ---------------------------------------------------------------------------

def threshold_setup(secret, t, n):
    """Returns (prime, shares). Hand one share to each authority."""
    prime = shamir_prime_for(secret)
    return prime, shamir_split(secret, t, n, prime)


def threshold_recover(shares, prime):
    """Give it any t shares; fewer than t returns a useless number."""
    return shamir_combine(shares, prime)


def partial_decrypt(c, share_exponent, nn):
    """Additive sharing only: each authority raises the ciphertext to its share."""
    return pow(c, share_exponent, nn)


def combine_partials(partials, nn):
    """The product of the partials equals c^(sum of shares) = c^secret."""
    total = 1
    for value in partials:
        total = (total * value) % nn
    return total


if __name__ == "__main__":
    from c14_homomorphic_encryption import (paillier_decrypt, paillier_encrypt,
                                            paillier_keygen, paillier_sum)

    print("--- Shamir 3-of-5 on a Paillier private exponent ---")
    pub, secret = paillier_keygen(512)
    prime, shares = threshold_setup(secret, 3, 5)
    for index, value in shares:
        print("  authority %d: %s" % (index, hex(value)[:20] + "..."))

    salaries = [52000, 61000, 48000, 95000, 73000]
    total = paillier_sum([paillier_encrypt(s, pub) for s in salaries], pub)
    print("  encrypted total:", hex(total)[:26] + "...")

    two = threshold_recover(shares[:2], prime)
    print("  2 of 5 recover the exponent correctly:", two == secret)
    print("  decryption with it:", str(paillier_decrypt(total, pub, two))[:22] + "...")

    three = threshold_recover(random.sample(shares, 3), prime)
    print("  3 of 5 recover the exponent correctly:", three == secret)
    print("  payroll total:", paillier_decrypt(total, pub, three), " real:", sum(salaries))

    print("\n--- additive 3-of-3, used as partial decryptions ---")
    pieces = additive_split(secret, 3)
    print("  shares sum back to the secret:", additive_combine(pieces) == secret)
    partials = [partial_decrypt(total, piece, pub["nn"]) for piece in pieces]
    rebuilt = combine_partials(partials, pub["nn"])
    direct = pow(total, secret, pub["nn"])
    print("  product of the three partials equals c^secret:", rebuilt == direct)
    print("  nobody ever held the whole exponent during that computation")

    print("\n--- splitting an AES key instead of an exponent ---")
    aes_key = int.from_bytes(b"0123456789abcdef", "big")
    prime2, key_shares = threshold_setup(aes_key, 2, 3)
    recovered = threshold_recover(key_shares[:2], prime2)
    print("  recovered key:", recovered.to_bytes(16, "big"))
