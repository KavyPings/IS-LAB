"""
CONCEPT 09 : DIGITAL SIGNATURES (all schemes in one place)
(Lab 6, and every scenario question)

THE PATTERN IS ALWAYS THE SAME:
   sign   : hash the message  ->  transform the hash with the PRIVATE key
   verify : hash the message  ->  check it with the PUBLIC key

What a signature gives you:
   Authentication (who sent it) + Integrity (not modified) + Non-repudiation.
It does NOT give confidentiality - encrypt separately for that.

ORDER IN A SCENARIO QUESTION
   "sign the hash of the encrypted record"  -> hash(ciphertext), then sign.
   "sign then encrypt"                      -> sign(plaintext), encrypt both.
   Read the question carefully; the marks are for the right order.
"""

from Crypto.PublicKey import RSA, DSA, ECC
from Crypto.Signature import pkcs1_15, pss, DSS
from Crypto.Hash import SHA256
import hashlib


# ---------------------------------------------------------------------------
# 1. RSA SIGNATURE  (most common answer)
# ---------------------------------------------------------------------------

def rsa_keys(bits=2048):
    k = RSA.generate(bits)
    return k, k.publickey()


def sign_rsa(message, private_key):
    data = message.encode() if isinstance(message, str) else message
    return pkcs1_15.new(private_key).sign(SHA256.new(data))


def verify_rsa(message, signature, public_key):
    data = message.encode() if isinstance(message, str) else message
    try:
        pkcs1_15.new(public_key).verify(SHA256.new(data), signature)
        return True
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------------------------
# 2. DSA SIGNATURE
# ---------------------------------------------------------------------------

def dsa_keys(bits=2048):
    k = DSA.generate(bits)
    return k, k.publickey()


def sign_dsa(message, private_key):
    data = message.encode() if isinstance(message, str) else message
    return DSS.new(private_key, "fips-186-3").sign(SHA256.new(data))


def verify_dsa(message, signature, public_key):
    data = message.encode() if isinstance(message, str) else message
    try:
        DSS.new(public_key, "fips-186-3").verify(SHA256.new(data), signature)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# 3. ECDSA SIGNATURE  (small keys, fast)
# ---------------------------------------------------------------------------

def ecdsa_keys(curve="P-256"):
    k = ECC.generate(curve=curve)
    return k, k.public_key()


def sign_ecdsa(message, private_key):
    data = message.encode() if isinstance(message, str) else message
    return DSS.new(private_key, "fips-186-3").sign(SHA256.new(data))


def verify_ecdsa(message, signature, public_key):
    data = message.encode() if isinstance(message, str) else message
    try:
        DSS.new(public_key, "fips-186-3").verify(SHA256.new(data), signature)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# 4. TEXTBOOK RSA SIGNATURE (when the question hands you n, e, d)
#    s = h^d mod n      verify: h == s^e mod n
# ---------------------------------------------------------------------------

def sign_rsa_manual(message, n, d):
    data = message.encode() if isinstance(message, str) else message
    h = int(hashlib.sha256(data).hexdigest(), 16) % n
    return pow(h, d, n)


def verify_rsa_manual(message, signature, n, e):
    data = message.encode() if isinstance(message, str) else message
    h = int(hashlib.sha256(data).hexdigest(), 16) % n
    return pow(signature, e, n) == h


def sign_hex_blob(hex_string, n, d):
    """Lab 6 Part 1 style: the 'signature' in the manual is just a big number
    written as 0x.. bytes. This converts hex -> int -> RSA operation."""
    m = int(hex_string.replace("0x", "").replace(" ", ""), 16)
    return pow(m % n, d, n)


def recover_signed_value(signature_int, n, e):
    """Apply the public key to a signature to see what was signed.
    That is literally what the online RSA tool in Lab 6 does."""
    v = pow(signature_int, e, n)
    b = v.to_bytes((v.bit_length() + 7) // 8 or 1, "big")
    return v, b


# ---------------------------------------------------------------------------
# 5. SIGN + ENCRYPT COMBINED (the full CIA triad in one helper)
#    Confidentiality = AES/RSA encryption
#    Integrity       = SHA-256 hash
#    Authenticity    = RSA signature
# ---------------------------------------------------------------------------

def secure_send(message, sender_private, receiver_public):
    """Returns a dict you can store in a file / database."""
    from Crypto.Cipher import PKCS1_OAEP, AES
    from Crypto.Random import get_random_bytes
    data = message.encode()
    digest = hashlib.sha256(data).hexdigest()              # INTEGRITY
    signature = sign_rsa(data, sender_private)             # AUTHENTICITY
    session = get_random_bytes(16)
    c = AES.new(session, AES.MODE_EAX)
    ct, tag = c.encrypt_and_digest(data)                   # CONFIDENTIALITY
    enc_key = PKCS1_OAEP.new(receiver_public).encrypt(session)
    return dict(enc_key=enc_key, nonce=c.nonce, tag=tag, ct=ct,
                hash=digest, signature=signature)


def secure_receive(pkt, receiver_private, sender_public):
    from Crypto.Cipher import PKCS1_OAEP, AES
    session = PKCS1_OAEP.new(receiver_private).decrypt(pkt["enc_key"])
    c = AES.new(session, AES.MODE_EAX, nonce=pkt["nonce"])
    data = c.decrypt_and_verify(pkt["ct"], pkt["tag"])
    ok_hash = hashlib.sha256(data).hexdigest() == pkt["hash"]
    ok_sig = verify_rsa(data, pkt["signature"], sender_public)
    return data.decode(), ok_hash, ok_sig


if __name__ == "__main__":
    priv, pub = rsa_keys(2048)
    s = sign_rsa("legal document", priv)
    print("RSA   :", verify_rsa("legal document", s, pub),
          verify_rsa("legal documenT", s, pub))

    dpriv, dpub = dsa_keys(2048)
    print("DSA   :", verify_dsa("x", sign_dsa("x", dpriv), dpub))

    epriv, epub = ecdsa_keys()
    print("ECDSA :", verify_ecdsa("x", sign_ecdsa("x", epriv), epub))

    n, e, d = priv.n, priv.e, priv.d
    sm = sign_rsa_manual("manual", n, d)
    print("manual:", verify_rsa_manual("manual", sm, n, e))

    rp, rpub = rsa_keys(2048)
    pkt = secure_send("Top secret", priv, rpub)
    print("CIA   :", secure_receive(pkt, rp, pub))
