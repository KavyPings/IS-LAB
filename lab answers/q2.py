import secrets
import logging
from datetime import datetime, timedelta


logging.basicConfig(
    filename="key_management.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


def is_prime(n, rounds=10):
    if n < 2:
        return False

    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]

    for p in small_primes:
        if n % p == 0:
            return n == p

    d = n - 1
    r = 0

    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)

            if x == n - 1:
                break
        else:
            return False

    return True


def generate_prime(bits):
    while True:
        n = secrets.randbits(bits)
        n |= (1 << (bits - 1))
        n |= 3

        if is_prime(n):
            return n


class RabinKeyManager:

    def __init__(self, key_size=1024):
        self.key_size = key_size
        self.keys = {}

    def generate_keys(self, facility):
        bits = self.key_size // 2

        p = generate_prime(bits)
        q = generate_prime(bits)

        while p == q:
            q = generate_prime(bits)

        n = p * q

        self.keys[facility] = {
            "public_key": n,
            "private_key": (p, q),
            "created": datetime.now(),
            "expires": datetime.now() + timedelta(days=365),
            "active": True
        }

        logging.info("Key generated for %s", facility)

    def get_keys(self, facility):
        if facility not in self.keys:
            return None

        if not self.keys[facility]["active"]:
            return None

        logging.info("Keys distributed to %s", facility)

        return self.keys[facility]

    def revoke_key(self, facility):
        if facility in self.keys:
            self.keys[facility]["active"] = False
            logging.info("Key revoked for %s", facility)

    def renew_key(self, facility):
        if facility in self.keys:
            self.generate_keys(facility)
            logging.info("Key renewed for %s", facility)

    def renew_expired_keys(self):
        for facility in self.keys:
            if datetime.now() >= self.keys[facility]["expires"]:
                self.renew_key(facility)


manager = RabinKeyManager(1024)

manager.generate_keys("Hospital A")
manager.generate_keys("Hospital B")
manager.generate_keys("Clinic C")

print("Facilities:")
for facility in manager.keys:
    print(facility)

print("\nHospital A Keys:")

keys = manager.get_keys("Hospital A")

print("Public Key:")
print(keys["public_key"])

print("\nPrivate Key:")
print(keys["private_key"])

print("\nRevoking Hospital B key...")

manager.revoke_key("Hospital B")

print("Hospital B Active:",
      manager.keys["Hospital B"]["active"])

print("\nRenewing Clinic C key...")

manager.renew_key("Clinic C")

print("Clinic C key renewed successfully.")

print("\nChecking expired keys...")

manager.renew_expired_keys()

print("Done.")
print("Audit log saved to key_management.log")