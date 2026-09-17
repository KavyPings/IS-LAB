"""
LAB 2 - ADDITIONAL 2
Encrypt two blocks of HEX data with DES, key "A1B2C3D4E5F60708".
  Block1: 54686973206973206120636f6e666964656e7469616c206d657373616765
  Block2: 416e64207468697320697320746865207365636f6e6420626c6f636b
  a) give the ciphertext for each block
  b) decrypt to recover the original plaintext blocks

CONCEPT: the DATA here is hex, not text. Decode it with bytes.fromhex()
before encrypting. The key "A1B2C3D4E5F60708" is 16 hex characters,
which decodes to exactly the 8 bytes DES needs.
"""

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

KEY = bytes.fromhex("A1B2C3D4E5F60708")        # 16 hex chars -> 8 bytes
BLOCK1 = "54686973206973206120636f6e666964656e7469616c206d657373616765"
BLOCK2 = "416e64207468697320697320746865207365636f6e6420626c6f636b"


def des_encrypt(data, key):
    return DES.new(key, DES.MODE_ECB).encrypt(pad(data, 8))


def des_decrypt(ct, key):
    return unpad(DES.new(key, DES.MODE_ECB).decrypt(ct), 8)


if __name__ == "__main__":
    print("key:", KEY.hex(), f"({len(KEY)} bytes)\n")

    for i, block_hex in enumerate((BLOCK1, BLOCK2), start=1):
        data = bytes.fromhex(block_hex)             # hex string -> raw bytes
        print(f"--- BLOCK {i} ---")
        print("hex in    :", block_hex)
        print("as text   :", data.decode(errors="replace"))
        print("length    :", len(data), "bytes")

        ct = des_encrypt(data, KEY)
        print("ciphertext:", ct.hex())

        pt = des_decrypt(ct, KEY)
        print("decrypted :", pt.decode(errors="replace"))
        print("matches   :", pt == data, "\n")
