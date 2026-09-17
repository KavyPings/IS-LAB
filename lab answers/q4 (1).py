from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

plaintext = "Classified Text"

key = b"1234567890ABCDEF12345678"
cipher = DES3.new(key, DES3.MODE_ECB)

ciphertext = cipher.encrypt(pad(plaintext.encode(), DES3.block_size))
print(key)
print("Plaintext :", plaintext)
print("Ciphertext:", ciphertext.hex().upper())

decipher = DES3.new(key, DES3.MODE_ECB)
decrypted = unpad(decipher.decrypt(ciphertext), DES3.block_size)

print("Decrypted :", decrypted.decode())