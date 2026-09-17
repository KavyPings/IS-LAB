"""
LAB 2 - ADDITIONAL 4
Encrypt "Secure Communication" using DES in CBC mode,
key = "A1B2C3D4", IV = "12345678". Then decrypt.

CONCEPT: CBC (Cipher Block Chaining)
  C_i = E_k( P_i XOR C_(i-1) )   with C_0 = IV
  * identical plaintext blocks now give different ciphertext blocks
  * the IV must be known to the receiver (normally prepended, not secret)
  * an error in one block affects that block and the next one only
"""

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

MESSAGE = "Secure Communication"
KEY = b"A1B2C3D4"                 # 8 bytes
IV = b"12345678"                  # 8 bytes - same as the block size


def des_cbc_encrypt(text, key, iv):
    return DES.new(key, DES.MODE_CBC, iv).encrypt(pad(text.encode(), 8))


def des_cbc_decrypt(ct, key, iv):
    return unpad(DES.new(key, DES.MODE_CBC, iv).decrypt(ct), 8).decode()


if __name__ == "__main__":
    print("message   :", MESSAGE)
    print("key       :", KEY.decode())
    print("IV        :", IV.decode())

    ct = des_cbc_encrypt(MESSAGE, KEY, IV)
    print("ciphertext:", ct.hex())
    print("blocks    :", [ct[i:i+8].hex() for i in range(0, len(ct), 8)])
    print("decrypted :", des_cbc_decrypt(ct, KEY, IV))

    print("\n--- why CBC beats ECB ---")
    repeated = "AAAAAAAAAAAAAAAA"                   # two identical blocks
    ecb = DES.new(KEY, DES.MODE_ECB).encrypt(pad(repeated.encode(), 8))
    cbc = DES.new(KEY, DES.MODE_CBC, IV).encrypt(pad(repeated.encode(), 8))
    print("plaintext 'AAAAAAAAAAAAAAAA'")
    print("  ECB blocks:", [ecb[i:i+8].hex() for i in range(0, 16, 8)],
          "<- identical, pattern leaks")
    print("  CBC blocks:", [cbc[i:i+8].hex() for i in range(0, 16, 8)],
          "<- different, no leak")
