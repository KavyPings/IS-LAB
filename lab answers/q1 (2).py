from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

plaintext = "Confidential Data"
key = b"A1B2C3D4"

cipher = DES.new(key, DES.MODE_ECB)

padded_text = pad(plaintext.encode(), DES.block_size)
ciphertext = cipher.encrypt(padded_text)

print("Plaintext :", plaintext)
print("Key       :", key.decode())
print("Ciphertext:", ciphertext.hex().upper())

decipher = DES.new(key, DES.MODE_ECB)
decrypted = unpad(decipher.decrypt(ciphertext), DES.block_size)

print("Decrypted :", decrypted.decode())