"""
LAB 3 - ADDITIONAL 4
Healthcare secure communication: implement ElGamal to encrypt patient
records, generate keys using the secp256r1 curve, encrypt with the
recipient's public key and decrypt with the private key. Measure
performance for data of varying sizes.

NOTE ON THE QUESTION
  "ElGamal on secp256r1" means EC-ElGamal: the same ElGamal structure
  (c1 = kG, shared = kQ) but with elliptic curve points instead of
  numbers mod p. For actual patient RECORDS (which are long), the shared
  point is hashed into an AES key - that is EC-ElGamal / ECIES.

  Both are implemented here:
     A) EC-ElGamal on secp256r1  <- what the question asks for
     B) classic ElGamal mod p    <- for comparison
"""

import time
import hashlib
import random
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES

RECORDS = {
    "short (100 B)": "Patient: R. Sharma | BP 130/85 | Allergy: penicillin" .ljust(100),
    "medium (10 KB)": "PATIENT HISTORY LINE\n" * 500,
    "large (100 KB)": "LAB RESULT ROW 12345 value=7.4 unit=mmol/L\n" * 2400,
}


# =================== A) EC-ELGAMAL over secp256r1 ==========================
def ec_elgamal_keygen(curve="P-256"):
    """private d, public Q = d*G"""
    key = ECC.generate(curve=curve)
    return key, key.public_key()


def ec_elgamal_encrypt(data, public_key):
    """c1 = k*G (sent) ; shared = k*Q ; AES key = SHA256(shared.x)"""
    k = ECC.generate(curve=public_key.curve)          # k and c1 = k*G
    shared = public_key.pointQ * k.d                  # k*Q
    aes_key = hashlib.sha256(
        int(shared.x).to_bytes(shared.size_in_bytes(), "big")).digest()
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(data.encode())
    return k.public_key(), cipher.nonce, tag, ct      # c1, nonce, tag, c2


def ec_elgamal_decrypt(c1, nonce, tag, ct, private_key):
    """shared = d*c1 = d*k*G = k*Q  -> same AES key"""
    shared = c1.pointQ * private_key.d
    aes_key = hashlib.sha256(
        int(shared.x).to_bytes(shared.size_in_bytes(), "big")).digest()
    return AES.new(aes_key, AES.MODE_GCM,
                   nonce=nonce).decrypt_and_verify(ct, tag).decode()


# =================== B) CLASSIC ELGAMAL mod p ==============================
def egcd(a, b):
    return (a, 1, 0) if b == 0 else (lambda g, x, y: (g, y, x - (a // b) * y))(*egcd(b, a % b))


def modinv(a, m):
    return egcd(a % m, m)[1] % m


P_2048 = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
             "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
             "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
             "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
             "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
             "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
             "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
             "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
             "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
             "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
             "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)


def classic_keygen():
    g = 2
    x = random.randrange(2, P_2048 - 2)
    return (P_2048, g, pow(g, x, P_2048)), x


def classic_encrypt(data, pub):
    """Hybrid: ElGamal protects an AES key (data is far bigger than p)."""
    p, g, h = pub
    k = random.randrange(2, p - 2)
    c1 = pow(g, k, p)
    s = pow(h, k, p)
    aes_key = hashlib.sha256(str(s).encode()).digest()
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(data.encode())
    return c1, cipher.nonce, tag, ct


def classic_decrypt(c1, nonce, tag, ct, x, p):
    s = pow(c1, x, p)
    aes_key = hashlib.sha256(str(s).encode()).digest()
    return AES.new(aes_key, AES.MODE_GCM,
                   nonce=nonce).decrypt_and_verify(ct, tag).decode()


if __name__ == "__main__":
    print("=== A) EC-ElGamal on secp256r1 (P-256) ===")
    t0 = time.perf_counter()
    priv, pub = ec_elgamal_keygen()
    print(f"key generation: {(time.perf_counter()-t0)*1000:.2f} ms")
    print(f"{'record':<16}{'bytes':>8}{'encrypt ms':>12}{'decrypt ms':>12}{'ok':>5}")
    for name, rec in RECORDS.items():
        t0 = time.perf_counter(); blob = ec_elgamal_encrypt(rec, pub)
        te = (time.perf_counter() - t0) * 1000
        t0 = time.perf_counter(); out = ec_elgamal_decrypt(*blob, priv)
        td = (time.perf_counter() - t0) * 1000
        print(f"{name:<16}{len(rec):>8}{te:>12.2f}{td:>12.2f}{str(out==rec):>5}")

    print("\n=== B) classic ElGamal mod p (2048-bit) ===")
    t0 = time.perf_counter()
    cpub, cx = classic_keygen()
    print(f"key generation: {(time.perf_counter()-t0)*1000:.2f} ms")
    print(f"{'record':<16}{'bytes':>8}{'encrypt ms':>12}{'decrypt ms':>12}{'ok':>5}")
    for name, rec in RECORDS.items():
        t0 = time.perf_counter(); blob = classic_encrypt(rec, cpub)
        te = (time.perf_counter() - t0) * 1000
        t0 = time.perf_counter(); out = classic_decrypt(*blob, cx, cpub[0])
        td = (time.perf_counter() - t0) * 1000
        print(f"{name:<16}{len(rec):>8}{te:>12.2f}{td:>12.2f}{str(out==rec):>5}")

    print("""
FINDINGS
  * EC-ElGamal on P-256 is far faster: one point multiplication (~1 ms)
    versus two 2048-bit modular exponentiations (~10-20 ms).
  * The ciphertext overhead is ~65 bytes for EC vs ~256 bytes for mod-p.
  * Both scale linearly with record size because the bulk work is AES.
  * For a hospital exchanging many small records, EC-ElGamal is the
    clear choice: less CPU, less bandwidth, same security level.
  * HIPAA-style compliance also needs auditing, access control and key
    rotation - see Lab 4.""")
