"""
LAB 2 - EXERCISE 1
Encrypt "Confidential Data" using DES with key "A1B2C3D4", then decrypt.

CONCEPT: DES is a 64-bit block cipher with a 56-bit effective key
(8 bytes given, 1 parity bit per byte is dropped).
  - key must be EXACTLY 8 bytes
  - data must be padded to a multiple of 8 bytes (PKCS#7)
  - ECB mode = each block encrypted independently (simplest, least secure)

NOTE ON THE KEY: "A1B2C3D4" is 8 ASCII characters, so we use it directly
as 8 bytes. (If a question gives 16 hex characters, decode them with
bytes.fromhex() instead - that also gives 8 bytes.)
"""

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

MESSAGE = "Confidential Data"
KEY = b"A1B2C3D4"                       # exactly 8 bytes


def des_encrypt(plaintext, key):
    cipher = DES.new(key, DES.MODE_ECB)          # create the cipher object
    padded = pad(plaintext.encode(), 8)          # 17 bytes -> 24 bytes
    return cipher.encrypt(padded)


def des_decrypt(ciphertext, key):
    cipher = DES.new(key, DES.MODE_ECB)          # same key, same mode
    return unpad(cipher.decrypt(ciphertext), 8).decode()


if __name__ == "__main__":
    print("message       :", MESSAGE)
    print("key           :", KEY.decode(), f"({len(KEY)} bytes)")
    print("padded length :", len(pad(MESSAGE.encode(), 8)), "bytes "
          f"(original {len(MESSAGE)})")

    ct = des_encrypt(MESSAGE, KEY)
    print("ciphertext hex:", ct.hex())
    print("ciphertext len:", len(ct), "bytes =", len(ct) // 8, "blocks")

    pt = des_decrypt(ct, KEY)
    print("decrypted     :", pt)
    print("match original:", pt == MESSAGE)
