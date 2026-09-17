"""
LAB 2 - ADDITIONAL 3
AES-256: encrypt "Encryption Strength" with key
"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
then decrypt.

The key string is 64 hex characters -> 32 bytes -> exactly AES-256.
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

MESSAGE = "Encryption Strength"
KEY = bytes.fromhex("0123456789ABCDEF" * 4)         # 64 hex chars -> 32 bytes


def aes256_encrypt(text, key):
    return AES.new(key, AES.MODE_ECB).encrypt(pad(text.encode(), 16))


def aes256_decrypt(ct, key):
    return unpad(AES.new(key, AES.MODE_ECB).decrypt(ct), 16).decode()


if __name__ == "__main__":
    print("message   :", MESSAGE)
    print("key       :", KEY.hex(), f"({len(KEY)} bytes -> AES-{len(KEY)*8})")
    ct = aes256_encrypt(MESSAGE, KEY)
    print("ciphertext:", ct.hex())
    print("blocks    :", len(ct) // 16)
    print("decrypted :", aes256_decrypt(ct, KEY))
