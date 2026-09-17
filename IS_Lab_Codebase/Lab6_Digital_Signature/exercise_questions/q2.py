"""
LAB 6 - EXERCISE 2
"Try using the Diffie-Hellman standard and verify the above steps."

IMPORTANT CONCEPT
  Diffie-Hellman is NOT a signature scheme - it only agrees on a shared
  secret. So "verify the above steps with DH" means one of two things, and
  both are implemented here:

  A) DH + HMAC  : the shared secret authenticates messages between the two
                  parties who ran the exchange. This gives integrity and
                  authentication BETWEEN THEM, but not non-repudiation
                  (either party could have made the tag, so neither can
                  prove to a third party who did).

  B) DH + DSA   : DH gives the confidential channel, a real signature
                  scheme (DSA, which is built on the same discrete-log
                  maths) gives non-repudiation. This is what real protocols
                  such as TLS do: signed Diffie-Hellman.

  The demo also shows the MAN-IN-THE-MIDDLE attack that unsigned DH allows.
"""

import random
import hashlib
import hmac

from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

# RFC 3526 group 14, 2048-bit
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


class Party:
    def __init__(self, name):
        self.name = name
        self.priv = random.randrange(2, P - 2)
        self.pub = pow(G, self.priv, P)
        self.key = None

    def derive(self, other_pub):
        shared = pow(other_pub, self.priv, P)
        raw = shared.to_bytes((shared.bit_length() + 7) // 8, "big")
        self.key = hashlib.sha256(raw).digest()
        return self.key

    # --- A) authentication with the shared key --------------------------
    def tag(self, message):
        return hmac.new(self.key, message.encode(), hashlib.sha256).hexdigest()

    def check(self, message, tag):
        return hmac.compare_digest(self.tag(message), tag)

    def encrypt(self, message):
        c = AES.new(self.key, AES.MODE_GCM)
        ct, t = c.encrypt_and_digest(message.encode())
        return c.nonce, t, ct

    def decrypt(self, nonce, t, ct):
        return AES.new(self.key, AES.MODE_GCM,
                       nonce=nonce).decrypt_and_verify(ct, t).decode()


if __name__ == "__main__":
    print("=" * 66)
    print("A) DIFFIE-HELLMAN + HMAC  (integrity between the two parties)")
    print("=" * 66)
    alice, bob = Party("Alice"), Party("Bob")
    print("STEP 0 - exchange public values over the open channel")
    print("  A =", str(alice.pub)[:50], "...")
    print("  B =", str(bob.pub)[:50], "...")
    alice.derive(bob.pub)
    bob.derive(alice.pub)
    print("  shared key identical:", alice.key == bob.key)
    print("  session key         :", alice.key.hex())

    doc = "Legal document from Alice"
    print("\nSTEP 1 - Alice 'signs' (tags) her document")
    t = alice.tag(doc)
    print("  HMAC:", t)

    print("\nSTEP 2 - Bob verifies")
    print("  valid:", bob.check(doc, t))

    doc2 = "RESPONSE DOCUMENT FROM BOB"
    print("\nSTEP 3 - Bob tags his own document")
    t2 = bob.tag(doc2)
    print("  HMAC:", t2)

    print("\nSTEP 4 - Alice verifies")
    print("  valid:", alice.check(doc2, t2))
    print("  tampered document:", alice.check(doc2 + "!", t2))

    print("\nconfidential channel built from the same key:")
    nonce, tg, ct = alice.encrypt("account number 5512-8890")
    print("  ciphertext:", ct.hex())
    print("  Bob reads :", bob.decrypt(nonce, tg, ct))

    print("\nLIMITATION: both parties hold the same key, so an HMAC does NOT")
    print("prove WHO created it. There is no non-repudiation.")

    print("\n" + "=" * 66)
    print("B) SIGNED DIFFIE-HELLMAN  (DH for secrecy + DSA for signatures)")
    print("=" * 66)
    alice_key = DSA.generate(2048)
    bob_key = DSA.generate(2048)
    print("DSA key pairs generated (same discrete-log maths as DH)")

    # each side signs its DH public value -> no man in the middle
    sig_a = DSS.new(alice_key, "fips-186-3").sign(SHA256.new(str(alice.pub).encode()))
    sig_b = DSS.new(bob_key, "fips-186-3").sign(SHA256.new(str(bob.pub).encode()))

    def verify_dh(pub_value, signature, verify_key):
        try:
            DSS.new(verify_key, "fips-186-3").verify(
                SHA256.new(str(pub_value).encode()), signature)
            return True
        except ValueError:
            return False

    print("  Bob checks Alice's signed DH value  :",
          verify_dh(alice.pub, sig_a, alice_key.publickey()))
    print("  Alice checks Bob's signed DH value  :",
          verify_dh(bob.pub, sig_b, bob_key.publickey()))

    print("\nSTEP 1-2 - Alice signs a document, Bob verifies")
    s = DSS.new(alice_key, "fips-186-3").sign(SHA256.new(doc.encode()))
    print("  signature:", s.hex()[:60], "...")
    try:
        DSS.new(alice_key.publickey(), "fips-186-3").verify(SHA256.new(doc.encode()), s)
        print("  valid    : True  -> this IS non-repudiable")
    except ValueError:
        print("  valid    : False")

    print("\n" + "=" * 66)
    print("MAN-IN-THE-MIDDLE on UNSIGNED Diffie-Hellman")
    print("=" * 66)
    mallory = Party("Mallory")
    # Mallory intercepts and substitutes her own public value both ways
    a_side, b_side = Party("Alice2"), Party("Bob2")
    a_side.derive(mallory.pub)         # Alice thinks she talks to Bob
    b_side.derive(mallory.pub)         # Bob thinks he talks to Alice
    print("  Alice's key == Bob's key :", a_side.key == b_side.key,
          " <- they never share a key with each other")
    print("  Mallory holds a separate key with each side and relays traffic.")
    print("  FIX: sign the DH public values, as in part B above.")
