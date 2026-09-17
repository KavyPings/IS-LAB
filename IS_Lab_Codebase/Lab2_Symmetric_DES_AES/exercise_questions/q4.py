"""
LAB 2 - EXERCISE 4
Encrypt "Classified Text" using Triple DES with key
"1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF", then decrypt.

CONCEPT: 3DES = DES applied three times, EDE order:
    C = E_k3( D_k2( E_k1(P) ) )
Key is K1|K2|K3, 8 bytes each = 24 bytes (48 hex characters).

TRAP IN THIS QUESTION
  The given key repeats every 8 bytes, so K1 == K2 == K3.
  Then 3DES collapses into plain single DES, and pycryptodome REFUSES it
  with "Triple DES key degenerates to single DES".
  Fix: change one bit of K2 so the three sub-keys are distinct.
  (Use bit 0x02, not 0x01 - bit 0 is the DES parity bit and gets reset.)
"""

from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

MESSAGE = "Classified Text"
KEY_HEX = "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF"


def build_3des_key(key_hex):
    k = bytes.fromhex(key_hex)                 # 48 hex chars -> 24 bytes
    k1, k2, k3 = k[:8], k[8:16], k[16:]
    print(f"  K1 = {k1.hex()}")
    print(f"  K2 = {k2.hex()}")
    print(f"  K3 = {k3.hex()}")
    if k1 == k2 or k2 == k3:
        print("  ! sub-keys are identical -> 3DES would degenerate to DES")
        k2 = bytes([k2[0] ^ 0x02]) + k2[1:]    # flip one non-parity bit
        print(f"  -> K2 adjusted to {k2.hex()}")
        k = k1 + k2 + k3
    return DES3.adjust_key_parity(k)           # library requires odd parity


def des3_encrypt(plaintext, key):
    return DES3.new(key, DES3.MODE_ECB).encrypt(pad(plaintext.encode(), 8))


def des3_decrypt(ciphertext, key):
    return unpad(DES3.new(key, DES3.MODE_ECB).decrypt(ciphertext), 8).decode()


if __name__ == "__main__":
    print("message :", MESSAGE)
    print("key hex :", KEY_HEX, f"({len(KEY_HEX)} hex chars = 24 bytes)")
    key = build_3des_key(KEY_HEX)
    print("final key:", key.hex())

    ct = des3_encrypt(MESSAGE, key)
    print("\nciphertext :", ct.hex())
    print("decrypted  :", des3_decrypt(ct, key))
