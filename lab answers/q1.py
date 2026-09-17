from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import secrets


class KeyManager:

    def __init__(self):
        self.keys = {}

    def generate_rsa_key(self, system):
        key = RSA.generate(2048)
        self.keys[system] = {
            "private": key,
            "public": key.publickey(),
            "active": True
        }

    def revoke_key(self, system):
        if system in self.keys:
            self.keys[system]["active"] = False

    def get_public_key(self, system):
        if system in self.keys and self.keys[system]["active"]:
            return self.keys[system]["public"]
        return None


class DiffieHellman:

    def __init__(self):
        self.p = 23
        self.g = 5

    def generate_private_key(self):
        return secrets.randbelow(self.p - 2) + 1

    def generate_public_key(self, private_key):
        return pow(self.g, private_key, self.p)

    def generate_shared_key(self, private_key, public_key):
        return pow(public_key, private_key, self.p)


def encrypt_message(message, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(message.encode())


def decrypt_message(ciphertext, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(ciphertext).decode()


key_manager = KeyManager()

systems = [
    "Finance System",
    "HR System",
    "Supply Chain System"
]

for system in systems:
    key_manager.generate_rsa_key(system)

print("RSA keys generated for:")
for system in systems:
    print("-", system)


print("\n--- Diffie-Hellman Key Exchange ---")

dh = DiffieHellman()

finance_private = dh.generate_private_key()
finance_public = dh.generate_public_key(finance_private)

hr_private = dh.generate_private_key()
hr_public = dh.generate_public_key(hr_private)

finance_shared = dh.generate_shared_key(
    finance_private,
    hr_public
)

hr_shared = dh.generate_shared_key(
    hr_private,
    finance_public
)

print("Finance Public Key :", finance_public)
print("HR Public Key      :", hr_public)
print("Finance Shared Key :", finance_shared)
print("HR Shared Key      :", hr_shared)

print(
    "Shared Secret Match:",
    finance_shared == hr_shared
)


print("\n--- RSA Secure Communication ---")

message = "Financial Report: Q4 Revenue = 5000000"

hr_public_key = key_manager.get_public_key("HR System")

encrypted = encrypt_message(
    message,
    hr_public_key
)

finance_private_key = key_manager.keys["HR System"]["private"]

decrypted = decrypt_message(
    encrypted,
    finance_private_key
)

print("Original Message :", message)
print("Encrypted Message:", encrypted.hex())
print("Decrypted Message:", decrypted)


print("\n--- Key Revocation ---")

key_manager.revoke_key("HR System")

print(
    "HR Key Active:",
    key_manager.keys["HR System"]["active"]
)

print(
    "HR Public Key Available:",
    key_manager.get_public_key("HR System") is not None
)


print("\n--- Adding New Subsystem ---")

key_manager.generate_rsa_key("New Subsidiary")

print(
    "New Subsidiary Key Available:",
    key_manager.get_public_key("New Subsidiary") is not None
)