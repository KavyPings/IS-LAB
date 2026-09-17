from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

plaintext = "Sensitive Information"

key = b"0123456789ABCDEF"

cipher = AES.new(key, AES.MODE_ECB)

ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))

print("Plaintext :", plaintext)
print("Ciphertext:", ciphertext.hex().upper())

decipher = AES.new(key, AES.MODE_ECB)
decrypted = unpad(decipher.decrypt(ciphertext), AES.block_size)

print("Decrypted :", decrypted.decode())