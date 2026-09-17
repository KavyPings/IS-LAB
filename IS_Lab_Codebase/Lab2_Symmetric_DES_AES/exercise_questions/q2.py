"""
LAB 2 - EXERCISE 2
Encrypt "Sensitive Information" with AES-128,
key = "0123456789ABCDEF0123456789ABCDEF", then decrypt.

READING THE KEY CORRECTLY - this is where marks are lost.
  The string is 32 characters.
  * As HEX it decodes to 16 bytes  -> AES-128  <- the question says AES-128
  * As ASCII it is 32 bytes        -> AES-256
  The question says AES-128, so we treat it as HEX.
Both versions are shown below so you can see the difference.

AES: 128-bit (16-byte) block, key of 16/24/32 bytes for AES-128/192/256.
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

MESSAGE = "Sensitive Information"
KEY_STR = "0123456789ABCDEF0123456789ABCDEF"
KEY = bytes.fromhex(KEY_STR)            # 32 hex chars -> 16 bytes -> AES-128


def aes_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(plaintext.encode(), 16))    # AES block = 16


def aes_decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), 16).decode()


if __name__ == "__main__":
    print("message    :", MESSAGE)
    print("key string :", KEY_STR)
    print("key bytes  :", KEY.hex(), f"({len(KEY)} bytes -> AES-{len(KEY)*8})")

    ct = aes_encrypt(MESSAGE, KEY)
    print("ciphertext :", ct.hex())
    print("decrypted  :", aes_decrypt(ct, KEY))

    print("\n--- if the same string is read as ASCII (32 bytes = AES-256) ---")
    key256 = KEY_STR.encode()
    ct2 = aes_encrypt(MESSAGE, key256)
    print("key bytes  :", key256.hex(), f"({len(key256)} bytes -> AES-256)")
    print("ciphertext :", ct2.hex())
    print("decrypted  :", aes_decrypt(ct2, key256))
