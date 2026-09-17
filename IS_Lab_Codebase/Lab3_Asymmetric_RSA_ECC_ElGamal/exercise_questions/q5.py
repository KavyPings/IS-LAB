"""
LAB 3 - EXERCISE 5
Peer-to-peer file sharing: implement Diffie-Hellman key exchange so two
peers establish a shared secret over an insecure channel. Measure the time
for key generation and key exchange.

CONCEPT
  public parameters p (large prime), g (generator)
  peer A: private a -> A = g^a mod p   (public, sent openly)
  peer B: private b -> B = g^b mod p
  A computes B^a mod p , B computes A^b mod p -> both get g^(ab) mod p
  An eavesdropper sees p, g, A, B but cannot compute g^(ab): discrete log.

WEAKNESS: plain DH has NO authentication, so it is vulnerable to a
man-in-the-middle. In practice the public values are signed (Lab 6).
"""

import time
import random
import hashlib
from Crypto.Cipher import AES

# RFC 3526 group 14 - a standard, safe 2048-bit prime. Use this instead of
# generating your own (which would take minutes).
P = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
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
G = 2


class Peer:
    """One node in the P2P network."""

    def __init__(self, name):
        self.name = name
        t0 = time.perf_counter()
        self.private = random.randrange(2, P - 2)       # secret exponent
        self.public = pow(G, self.private, P)           # g^private mod p
        self.keygen_time = time.perf_counter() - t0
        self.shared = None

    def exchange(self, other_public):
        t0 = time.perf_counter()
        self.shared = pow(other_public, self.private, P)
        self.exchange_time = time.perf_counter() - t0
        return self.shared

    def session_key(self):
        """Hash the shared number into a 32-byte AES key."""
        raw = self.shared.to_bytes((self.shared.bit_length() + 7) // 8, "big")
        return hashlib.sha256(raw).digest()

    def send_file(self, data):
        c = AES.new(self.session_key(), AES.MODE_GCM)
        ct, tag = c.encrypt_and_digest(data)
        return c.nonce, tag, ct

    def receive_file(self, nonce, tag, ct):
        return AES.new(self.session_key(), AES.MODE_GCM,
                       nonce=nonce).decrypt_and_verify(ct, tag)


if __name__ == "__main__":
    print("public parameters: 2048-bit MODP group 14, g =", G)

    alice, bob = Peer("Alice"), Peer("Bob")
    print(f"\nkey generation")
    print(f"  Alice: {alice.keygen_time*1000:8.2f} ms")
    print(f"  Bob  : {bob.keygen_time*1000:8.2f} ms")

    print("\npublic values exchanged over the INSECURE channel:")
    print("  A =", str(alice.public)[:60], "...")
    print("  B =", str(bob.public)[:60], "...")

    alice.exchange(bob.public)
    bob.exchange(alice.public)
    print(f"\nkey exchange")
    print(f"  Alice: {alice.exchange_time*1000:8.2f} ms")
    print(f"  Bob  : {bob.exchange_time*1000:8.2f} ms")

    print("\nshared secret equal:", alice.shared == bob.shared)
    print("  secret :", str(alice.shared)[:60], "...")
    print("  AES key:", alice.session_key().hex())

    print("\nusing the shared key to transfer a file chunk:")
    nonce, tag, ct = alice.send_file(b"peer-to-peer file chunk 001")
    print("  ciphertext:", ct.hex())
    print("  Bob reads :", bob.receive_file(nonce, tag, ct).decode())

    print("\nadding a third peer (scalability):")
    carol = Peer("Carol")
    alice_c = pow(carol.public, alice.private, P)
    carol_a = pow(alice.public, carol.private, P)
    print("  Alice-Carol share a DIFFERENT secret:", alice_c == carol_a,
          "| same as Alice-Bob?", alice_c == alice.shared)
    print("  -> n peers need n(n-1)/2 pairwise exchanges")
