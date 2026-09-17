"""
LAB 2 - ADDITIONAL 5
Encrypt "Cryptography Lab Exercise" using AES in CTR mode,
key = "0123456789ABCDEF0123456789ABCDEF", nonce = "0000000000000000".
Then decrypt.

CONCEPT: CTR (Counter mode)
  keystream_i = E_k(nonce || counter_i)
  C_i = P_i XOR keystream_i
  * turns AES into a STREAM cipher -> NO PADDING needed
  * encryption and decryption are the identical operation
  * blocks are independent -> can be done in parallel (fastest mode)
  * the nonce must NEVER be reused with the same key
"""

from Crypto.Cipher import AES
from Crypto.Util import Counter

MESSAGE = "Cryptography Lab Exercise"
KEY = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF")   # 16 bytes -> AES-128
NONCE = bytes.fromhex("0000000000000000")                 # 8 bytes


def aes_ctr(data, key, nonce):
    """Same function encrypts AND decrypts - CTR is symmetric XOR."""
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.encrypt(data)


if __name__ == "__main__":
    print("message   :", MESSAGE, f"({len(MESSAGE)} bytes)")
    print("key       :", KEY.hex(), f"({len(KEY)} bytes)")
    print("nonce     :", NONCE.hex())

    ct = aes_ctr(MESSAGE.encode(), KEY, NONCE)
    print("ciphertext:", ct.hex())
    print("ct length :", len(ct), "bytes  <- SAME as plaintext, no padding")

    pt = aes_ctr(ct, KEY, NONCE)                # identical call decrypts
    print("decrypted :", pt.decode())

    print("\nkeystream check: ciphertext XOR plaintext = keystream")
    ks = bytes(a ^ b for a, b in zip(ct, MESSAGE.encode()))
    print("  keystream :", ks.hex())
