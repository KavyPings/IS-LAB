"""
CONCEPT 07 : DIFFIE-HELLMAN KEY EXCHANGE
(Lab 3 Q5, Lab 4 Q1, Lab 6 Q2)

Goal: two parties who have NEVER met agree on a shared secret over an
open channel. DH does NOT encrypt and does NOT authenticate - it only
produces a shared key, which you then feed to AES.

  public parameters : prime p, generator g
  Alice: private a  ->  A = g^a mod p   (sent to Bob)
  Bob  : private b  ->  B = g^b mod p   (sent to Alice)
  Alice computes  s = B^a mod p
  Bob   computes  s = A^b mod p
  Both get  g^(ab) mod p  -> same number.

Eve sees p, g, A, B but cannot get a or b (discrete logarithm problem).
"""

import random
import hashlib
import time

# RFC 3526 MODP Group 14 (2048-bit). Standard, safe, and instant to use -
# far better in an exam than generating your own 2048-bit safe prime.
P_2048 = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
G_2048 = 2


class DHParty:
    """One peer in a Diffie-Hellman exchange."""

    def __init__(self, name, p=P_2048, g=G_2048):
        self.name = name
        self.p, self.g = p, g
        self.private = random.randrange(2, p - 2)     # secret exponent
        self.public = pow(g, self.private, p)         # g^private mod p
        self.shared = None

    def compute_shared(self, other_public):
        """s = other_public ^ my_private mod p"""
        self.shared = pow(other_public, self.private, self.p)
        return self.shared

    def session_key(self):
        """Hash the shared number down to a 32-byte AES key.
        NEVER use the raw DH number as an AES key - always hash it."""
        b = self.shared.to_bytes((self.shared.bit_length() + 7) // 8, "big")
        return hashlib.sha256(b).digest()


def dh_exchange(p=P_2048, g=G_2048, verbose=True):
    """Full exchange between two peers; returns (alice, bob, timings)."""
    t0 = time.perf_counter()
    alice = DHParty("Alice", p, g)
    bob = DHParty("Bob", p, g)
    t_keygen = time.perf_counter() - t0

    t0 = time.perf_counter()
    alice.compute_shared(bob.public)          # exchange public values
    bob.compute_shared(alice.public)
    t_exchange = time.perf_counter() - t0

    if verbose:
        print(f"Alice public : {str(alice.public)[:40]}...")
        print(f"Bob   public : {str(bob.public)[:40]}...")
        print(f"secrets match: {alice.shared == bob.shared}")
        print(f"key gen  time: {t_keygen*1000:.2f} ms")
        print(f"exchange time: {t_exchange*1000:.2f} ms")
    return alice, bob, (t_keygen, t_exchange)


def dh_small_demo(p=23, g=5, a=6, b=15):
    """Textbook numbers you can write out by hand in a viva."""
    A, B = pow(g, a, p), pow(g, b, p)
    s1, s2 = pow(B, a, p), pow(A, b, p)
    print(f"p={p} g={g} | a={a} A={A} | b={b} B={B} | shared={s1}=={s2}")
    return s1


# ---------------------------------------------------------------------------
# Using the DH key: encrypt a message with AES once both sides share a key
# ---------------------------------------------------------------------------

def dh_secure_message(sender, receiver, message):
    """sender/receiver are DHParty objects that already ran compute_shared."""
    from Crypto.Cipher import AES
    key = sender.session_key()
    c = AES.new(key, AES.MODE_EAX)
    ct, tag = c.encrypt_and_digest(message.encode())
    # receiver side
    d = AES.new(receiver.session_key(), AES.MODE_EAX, nonce=c.nonce)
    return d.decrypt_and_verify(ct, tag).decode()


if __name__ == "__main__":
    dh_small_demo()
    a, b, _ = dh_exchange()
    print("message through DH key:", dh_secure_message(a, b, "meet at 5pm"))
