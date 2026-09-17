"""
CONCEPT 10 : KEY MANAGEMENT SYSTEM (KMS)
(Lab 4 - SecureCorp / HealthCare / DigiRights questions)

Every "build a centralized key management service" question wants the same
six operations. Copy this class and change the algorithm inside _make_keys().

  1. Key GENERATION   - create a key pair per entity
  2. Key DISTRIBUTION - hand out the public key (and private key to its owner)
  3. Key REVOCATION   - mark a key dead so it stops being usable
  4. Key RENEWAL      - rotate keys after a time period
  5. SECURE STORAGE   - private keys encrypted at rest (AES + master password)
  6. AUDIT LOGGING    - append a timestamped line for every operation
"""

import os
import json
import time
import hashlib
from datetime import datetime, timedelta
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2      # password -> AES key


# ---------------------------------------------------------------------------
# SECURE STORAGE HELPERS  (encrypt private keys before writing to disk)
# ---------------------------------------------------------------------------

def derive_master_key(password, salt):
    """PBKDF2: slow on purpose, so guessing the password is expensive."""
    return PBKDF2(password, salt, dkLen=32, count=100_000)


def encrypt_blob(data, password):
    """Returns salt + nonce + tag + ciphertext, all in one bytes object."""
    salt = get_random_bytes(16)
    key = derive_master_key(password, salt)
    c = AES.new(key, AES.MODE_GCM)
    ct, tag = c.encrypt_and_digest(data)
    return salt + c.nonce + tag + ct


def decrypt_blob(blob, password):
    salt, nonce, tag, ct = blob[:16], blob[16:32], blob[32:48], blob[48:]
    key = derive_master_key(password, salt)
    return AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)


# ---------------------------------------------------------------------------
# AUDIT LOG
# ---------------------------------------------------------------------------

class AuditLog:
    """Append-only log. Every KMS question asks for 'auditing and logging'."""

    def __init__(self, path="audit.log"):
        self.path = path
        self.entries = []

    def record(self, actor, action, detail=""):
        line = f"{datetime.now().isoformat(timespec='seconds')} | {actor} | {action} | {detail}"
        self.entries.append(line)
        with open(self.path, "a") as f:
            f.write(line + "\n")
        return line

    def show(self, n=20):
        for line in self.entries[-n:]:
            print("  " + line)


# ---------------------------------------------------------------------------
# THE KEY MANAGEMENT SERVICE
# ---------------------------------------------------------------------------

class KeyManagementService:

    def __init__(self, master_password="master-secret", key_bits=2048,
                 lifetime_days=365, store_dir="kms_store"):
        self.master_password = master_password
        self.key_bits = key_bits
        self.lifetime = timedelta(days=lifetime_days)
        self.store_dir = store_dir
        os.makedirs(store_dir, exist_ok=True)
        self.registry = {}          # entity -> metadata dict
        self.log = AuditLog(os.path.join(store_dir, "audit.log"))

    # --- 1. GENERATION ----------------------------------------------------
    def generate(self, entity):
        key = RSA.generate(self.key_bits)
        priv_pem = key.export_key()
        pub_pem = key.publickey().export_key()
        # store the PRIVATE key encrypted; the public key in clear
        with open(self._path(entity, "priv.enc"), "wb") as f:
            f.write(encrypt_blob(priv_pem, self.master_password))
        with open(self._path(entity, "pub.pem"), "wb") as f:
            f.write(pub_pem)
        self.registry[entity] = dict(
            created=datetime.now().isoformat(timespec="seconds"),
            expires=(datetime.now() + self.lifetime).isoformat(timespec="seconds"),
            revoked=False,
            fingerprint=hashlib.sha256(pub_pem).hexdigest()[:16])
        self.log.record(entity, "KEY_GENERATED", f"{self.key_bits}-bit RSA")
        return pub_pem

    # --- 2. DISTRIBUTION --------------------------------------------------
    def get_public_key(self, entity):
        """Anyone may fetch a public key - unless it has been revoked."""
        self._check_active(entity)
        self.log.record(entity, "PUBLIC_KEY_ISSUED")
        with open(self._path(entity, "pub.pem"), "rb") as f:
            return RSA.import_key(f.read())

    def get_private_key(self, entity, password):
        """Only with the master password. Decrypts the stored blob."""
        self._check_active(entity)
        with open(self._path(entity, "priv.enc"), "rb") as f:
            pem = decrypt_blob(f.read(), password)
        self.log.record(entity, "PRIVATE_KEY_ISSUED")
        return RSA.import_key(pem)

    # --- 3. REVOCATION ----------------------------------------------------
    def revoke(self, entity, reason="unspecified"):
        self.registry[entity]["revoked"] = True
        self.registry[entity]["revoked_at"] = datetime.now().isoformat(timespec="seconds")
        self.log.record(entity, "KEY_REVOKED", reason)

    # --- 4. RENEWAL -------------------------------------------------------
    def renew(self, entity):
        """Throw the old pair away and issue a new one."""
        self.log.record(entity, "KEY_RENEWAL_STARTED")
        self.generate(entity)
        self.registry[entity]["revoked"] = False
        return self.registry[entity]

    def renew_expired(self):
        """Call this periodically - renews everything past its expiry date."""
        now = datetime.now()
        renewed = []
        for e, meta in list(self.registry.items()):
            if datetime.fromisoformat(meta["expires"]) <= now:
                self.renew(e)
                renewed.append(e)
        return renewed

    # --- helpers ----------------------------------------------------------
    def _path(self, entity, suffix):
        return os.path.join(self.store_dir, f"{entity}_{suffix}")

    def _check_active(self, entity):
        if entity not in self.registry:
            raise KeyError(f"{entity} has no keys")
        if self.registry[entity]["revoked"]:
            raise PermissionError(f"{entity}'s key is REVOKED")

    def status(self):
        print(f"{'entity':<12}{'created':<21}{'expires':<21}{'revoked'}")
        for e, m in self.registry.items():
            print(f"{e:<12}{m['created']:<21}{m['expires']:<21}{m['revoked']}")


if __name__ == "__main__":
    kms = KeyManagementService(key_bits=1024, store_dir="/tmp/kms_demo")
    for org in ("FinanceSystem", "HRSystem", "SupplyChain"):
        kms.generate(org)
    kms.status()
    pub = kms.get_public_key("HRSystem")
    kms.revoke("HRSystem", "compromised laptop")
    try:
        kms.get_public_key("HRSystem")
    except PermissionError as err:
        print("blocked:", err)
    kms.renew("HRSystem")
    print("after renewal:")
    kms.status()
    print("audit log:")
    kms.log.show()
