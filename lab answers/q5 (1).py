from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

plaintext = "Top Secret Data"

key = b"FEDCBA9876543210FEDCBA98"

cipher = AES.new(key, AES.MODE_ECB)

print("----- AES-192 Encryption -----")
print("Plaintext :", plaintext)
print("Key       :", key.decode())

print("\nStep 1 : Key Expansion")
print("24-byte key expanded into 13 round keys internally.")

print("\nStep 2 : Initial Round")
print("Initial AddRoundKey performed internally.")

print("\nStep 3 : Main Rounds")
print("Rounds 1-11:")
print("SubBytes -> ShiftRows -> MixColumns -> AddRoundKey")

ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))

print("\nStep 4 : Final Round")
print("SubBytes -> ShiftRows -> AddRoundKey")

print("\nCiphertext (Hex):")
print(ciphertext.hex().upper())

decipher = AES.new(key, AES.MODE_ECB)

decrypted = unpad(decipher.decrypt(ciphertext), AES.block_size)

print("\n----- AES-192 Decryption -----")
print("Recovered Plaintext:", decrypted.decode())