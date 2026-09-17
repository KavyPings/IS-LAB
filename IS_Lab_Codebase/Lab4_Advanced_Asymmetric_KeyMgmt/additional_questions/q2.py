"""
LAB 4 - ADDITIONAL 2 : XYZ Logistics - attacking a weak RSA key

Eve exploits a vulnerability in key generation: the primes p and q are not
large enough or not random enough. Demonstrate the attack and discuss
mitigation.

THREE ATTACKS ARE SHOWN
  1. SMALL MODULUS      - n is short enough to trial-divide / factor outright.
  2. CLOSE PRIMES       - p and q are near each other, so Fermat's method
                          factors n in a handful of steps.
                          n = a^2 - b^2 = (a-b)(a+b)
  3. SHARED PRIME       - two users' moduli share a prime, so gcd(n1, n2)
                          reveals it instantly (a real-world internet-wide bug).

Once p and q are known:  phi = (p-1)(q-1),  d = e^-1 mod phi  -> full private key.
"""

import math
import random
import time


def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x, y = egcd(b, a % b)
    return (g, y, x - (a // b) * y)


def modinv(a, m):
    return egcd(a % m, m)[1] % m


def is_prime(n, k=20):
    if n < 2:
        return False
    for sp in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % sp == 0:
            return n == sp
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def next_prime(n):
    n |= 1
    while not is_prime(n):
        n += 2
    return n


# ---------------------------------------------------------------- attacks
def trial_division(n, limit=10_000_000):
    """Works when n is small. Try every factor up to sqrt(n)."""
    if n % 2 == 0:
        return 2, n // 2
    f = 3
    while f * f <= n and f < limit:
        if n % f == 0:
            return f, n // f
        f += 2
    return None


def fermat_factor(n, max_steps=1_000_000):
    """Fast when p and q are CLOSE: search a with a^2 - n a perfect square."""
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for step in range(max_steps):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            return a - b, a + b, step + 1
        a += 1
    return None


def shared_prime_attack(n1, n2):
    """If two moduli share a prime, gcd finds it in microseconds."""
    g = math.gcd(n1, n2)
    return None if g == 1 else (g, n1 // g, n2 // g)


def recover_private_key(p, q, e):
    phi = (p - 1) * (q - 1)
    return modinv(e, phi)


def rsa_dec(c, d, n):
    m = pow(c, d, n)
    return m.to_bytes((m.bit_length() + 7) // 8 or 1, "big")


def rsa_enc(msg, e, n):
    return pow(int.from_bytes(msg.encode(), "big"), e, n)


if __name__ == "__main__":
    E = 65537
    SECRET = "XYZ shipment codes"

    # ============================ ATTACK 1 ================================
    print("=== ATTACK 1 : modulus far too small ===")
    p, q = 60013, 60077                       # ~16-bit primes
    n = p * q
    d = recover_private_key(p, q, E)
    print(f"  n = {n} ({n.bit_length()} bits)")
    t0 = time.perf_counter()
    fp, fq = trial_division(n)
    print(f"  trial division found p={fp}, q={fq} in "
          f"{(time.perf_counter()-t0)*1000:.2f} ms")
    print(f"  recovered d = {recover_private_key(fp, fq, E)} "
          f"(real d = {d}) -> match: {recover_private_key(fp, fq, E) == d}")

    # ============================ ATTACK 2 ================================
    print("\n=== ATTACK 2 : p and q chosen too close together ===")
    base = random.getrandbits(256) | (1 << 255)
    p = next_prime(base)
    q = next_prime(p + 1000)                  # deliberately adjacent
    n = p * q
    d = recover_private_key(p, q, E)
    c = rsa_enc(SECRET, E, n)
    print(f"  n has {n.bit_length()} bits - far too big for trial division")
    print(f"  |p - q| = {abs(p-q)}  <- the fatal mistake")

    t0 = time.perf_counter()
    fp, fq, steps = fermat_factor(n)
    dt = (time.perf_counter() - t0) * 1000
    print(f"  Fermat factorisation succeeded in {steps} steps, {dt:.2f} ms")
    print(f"  p recovered : {str(fp)[:40]}...")
    print(f"  q recovered : {str(fq)[:40]}...")
    d_eve = recover_private_key(fp, fq, E)
    print(f"  d matches the real private key: {d_eve == d}")
    print(f"  Eve decrypts: {rsa_dec(c, d_eve, n).decode()}")

    # ============================ ATTACK 3 ================================
    print("\n=== ATTACK 3 : two keys share a prime ===")
    shared = next_prime(random.getrandbits(256) | (1 << 255))
    q1 = next_prime(random.getrandbits(256) | (1 << 255))
    q2 = next_prime(random.getrandbits(256) | (1 << 255))
    n1, n2 = shared * q1, shared * q2
    t0 = time.perf_counter()
    g, a, b = shared_prime_attack(n1, n2)
    print(f"  gcd(n1, n2) found the shared prime in "
          f"{(time.perf_counter()-t0)*1000:.3f} ms")
    print(f"  shared prime correct: {g == shared}")
    print("  -> BOTH private keys fall at once")

    print("""
=== MITIGATION - how XYZ Logistics should fix this ===

1. KEY SIZE
   Use at least 2048-bit moduli (3072 for long-term data). A 32-bit or even
   512-bit modulus is factored on a laptop.

2. PRIME DISTANCE
   p and q must be independently random and differ in their high bits.
   Standards require |p - q| > 2^(nlen/2 - 100). If the primes are close,
   Fermat's method breaks the key in milliseconds - as shown above.

3. RANDOMNESS SOURCE
   Generate primes from a cryptographically secure RNG (os.urandom /
   Crypto.Random), never from time(), a PRNG seed, or a fixed pool.
   The 2012 "Ron was wrong, Whit is right" study found thousands of real
   TLS keys sharing primes because of weak entropy at boot.

4. USE A VETTED LIBRARY
   Crypto.PublicKey.RSA.generate() already enforces the distance and
   primality checks. Do not hand-roll key generation in production.

5. PADDING
   Use OAEP for encryption and PSS for signatures. Textbook RSA is
   deterministic and malleable.

6. OPERATIONAL CONTROLS
   Rotate keys regularly, revoke immediately on suspicion, keep private
   keys in an HSM or encrypted at rest, and log every key operation
   (see the key management service in exercise q2.py).

7. DETECTION
   Periodically run gcd across all deployed moduli - if any pair shares a
   factor, both keys are already compromised.""")
