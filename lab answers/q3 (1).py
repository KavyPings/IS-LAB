from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad
import time

plaintext = "Performance Testing of Encryption Algorithms".encode()

des_key = b"A1B2C3D4"

aes_key = b"0123456789ABCDEF0123456789ABCDEF"

des_cipher = DES.new(des_key, DES.MODE_ECB)

start = time.perf_counter()
des_ciphertext = des_cipher.encrypt(pad(plaintext, DES.block_size))
des_encrypt_time = time.perf_counter() - start

start = time.perf_counter()
des_plaintext = unpad(des_cipher.decrypt(des_ciphertext), DES.block_size)
des_decrypt_time = time.perf_counter() - start

aes_cipher = AES.new(aes_key, AES.MODE_ECB)

start = time.perf_counter()
aes_ciphertext = aes_cipher.encrypt(pad(plaintext, AES.block_size))
aes_encrypt_time = time.perf_counter() - start

start = time.perf_counter()
aes_plaintext = unpad(aes_cipher.decrypt(aes_ciphertext), AES.block_size)
aes_decrypt_time = time.perf_counter() - start

print("\nOriginal Message :", plaintext.decode())

print("\nDES")
print("Ciphertext (Hex):", des_ciphertext.hex().upper())
print("Decrypted:", des_plaintext.decode())
print("Encryption Time: {:.10f} seconds".format(des_encrypt_time))
print("Decryption Time: {:.10f} seconds".format(des_decrypt_time))

print("\nAES-256")
print("Ciphertext (Hex):", aes_ciphertext.hex().upper())
print("Decrypted:", aes_plaintext.decode())
print("Encryption Time: {:.10f} seconds".format(aes_encrypt_time))
print("Decryption Time: {:.10f} seconds".format(aes_decrypt_time))

print("\nComparison")
print("{:<10} {:<20} {:<20}".format("Algorithm", "Encryption(s)", "Decryption(s)"))
print("{:<10} {:<20.10f} {:<20.10f}".format("DES", des_encrypt_time, des_decrypt_time))
print("{:<10} {:<20.10f} {:<20.10f}".format("AES-256", aes_encrypt_time, aes_decrypt_time))