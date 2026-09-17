from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

private_key = ECC.generate(curve="P-256")
public_key = private_key.public_key()

print("ECC Curve: P-256")
print("Private Key generated")
print("Public Key generated")

message = "Secure Transactions"

ephemeral_key = ECC.generate(curve="P-256")

shared_point = ephemeral_key.d * public_key.pointQ

shared_secret = int(shared_point.x).to_bytes(32, byteorder="big")

aes_key = SHA256.new(shared_secret).digest()

nonce = get_random_bytes(12)

cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)

ciphertext, tag = cipher.encrypt_and_digest(message.encode())

print("\n----- Encryption -----")
print("Original Message :", message)
print("Ciphertext (Hex) :", ciphertext.hex())
print("Nonce            :", nonce.hex())
print("Tag              :", tag.hex())

shared_point = private_key.d * ephemeral_key.public_key().pointQ

shared_secret = int(shared_point.x).to_bytes(32, byteorder="big")

aes_key = SHA256.new(shared_secret).digest()

decipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)

decrypted = decipher.decrypt_and_verify(ciphertext, tag)

print("\n----- Decryption -----")
print("Decrypted Message :", decrypted.decode())