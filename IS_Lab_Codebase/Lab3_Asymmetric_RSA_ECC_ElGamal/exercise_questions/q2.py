"""
LAB 3 - EXERCISE 2
Using ECC, encrypt "Secure Transactions" with the public key, then decrypt.

IMPORTANT CONCEPT
  ECC by itself cannot encrypt a message - it is a key-agreement and
  signature system. The standard way to "encrypt with ECC" is ECIES:

     1. generate a ONE-TIME (ephemeral) EC key pair
     2. ECDH: shared_point = ephemeral_private * recipient_public
     3. AES key = SHA-256( x coordinate of shared_point )
     4. AES-encrypt the message with that key
     5. send: ephemeral_public + nonce + tag + ciphertext

  The recipient recomputes the SAME shared point as
     recipient_private * ephemeral_public
  because  a*(b*G) == b*(a*G).
"""

import hashlib
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES

MESSAGE = "Secure Transactions"


def shared_key(private_key, public_key):
    """ECDH: multiply their public point by my private scalar, hash the x."""
    point = public_key.pointQ * private_key.d
    # size_in_bytes() adapts to the curve (32 for P-256, 66 for P-521)
    return hashlib.sha256(int(point.x).to_bytes(point.size_in_bytes(), "big")).digest()


def ecc_encrypt(message, recipient_public):
    eph = ECC.generate(curve=recipient_public.curve)     # step 1
    key = shared_key(eph, recipient_public)              # steps 2-3
    cipher = AES.new(key, AES.MODE_EAX)                  # step 4
    ct, tag = cipher.encrypt_and_digest(message.encode())
    return eph.public_key(), cipher.nonce, tag, ct       # step 5


def ecc_decrypt(eph_public, nonce, tag, ct, my_private):
    key = shared_key(my_private, eph_public)             # same shared secret
    return AES.new(key, AES.MODE_EAX, nonce=nonce).decrypt_and_verify(ct, tag)


if __name__ == "__main__":
    receiver = ECC.generate(curve="P-256")               # secp256r1
    print("curve          : P-256 (secp256r1)")
    print("private key d  :", str(receiver.d)[:50], "...")
    print("public key Q.x :", str(receiver.pointQ.x)[:50], "...")
    print("public key Q.y :", str(receiver.pointQ.y)[:50], "...")

    eph_pub, nonce, tag, ct = ecc_encrypt(MESSAGE, receiver.public_key())
    print("\nmessage        :", MESSAGE)
    print("ephemeral Q.x  :", str(eph_pub.pointQ.x)[:50], "...")
    print("ciphertext     :", ct.hex())
    print("auth tag       :", tag.hex())

    pt = ecc_decrypt(eph_pub, nonce, tag, ct, receiver)
    print("decrypted      :", pt.decode())

    # proof that both sides derive the same key
    k1 = shared_key(receiver, eph_pub)
    print("\nshared key (receiver side):", k1.hex()[:32], "...")
