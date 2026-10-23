"""
Pure-Python PKCS#1 OAEP (RFC 8017), a drop-in for Crypto.Cipher.PKCS1_OAEP.

pycryptodome's own OAEP calls a native constant-time decoder, so the whole
module is replaced rather than patched. Defaults match pycryptodome: SHA-1 as
the OAEP hash and MGF1 with the same hash, so a ciphertext produced on a
machine with working native modules still decrypts here, and the other way
round.
"""

import os


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def mgf1(seed, length, hash_module):
    """The mask generation function from RFC 8017 appendix B.2.1."""
    out = b""
    counter = 0
    while len(out) < length:
        out += hash_module.new(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


class PKCS1OAEPCipher:
    def __init__(self, key, hashAlgo=None, mgfunc=None, label=b"", randfunc=None):
        self._key = key
        if hashAlgo is None:
            from Crypto.Hash import SHA1
            hashAlgo = SHA1
        self._hash = hashAlgo
        self._mgf = mgfunc or (lambda seed, length: mgf1(seed, length, self._hash))
        self._label = label if isinstance(label, bytes) else bytes(label)
        self._rand = randfunc or os.urandom

    # ------------------------------------------------------------------
    def can_encrypt(self):
        return True

    def can_decrypt(self):
        return True

    def _size(self):
        return (self._key.n.bit_length() + 7) // 8

    # ------------------------------------------------------------------
    def encrypt(self, message):
        k = self._size()
        h_len = self._hash.digest_size
        m_len = len(message)
        if m_len > k - 2 * h_len - 2:
            raise ValueError("Plaintext is too long.")

        l_hash = self._hash.new(self._label).digest()
        padding = b"\x00" * (k - m_len - 2 * h_len - 2)
        db = l_hash + padding + b"\x01" + bytes(message)

        seed = self._rand(h_len)
        masked_db = _xor(db, self._mgf(seed, k - h_len - 1))
        masked_seed = _xor(seed, self._mgf(masked_db, h_len))
        em = b"\x00" + masked_seed + masked_db

        value = pow(int.from_bytes(em, "big"), self._key.e, self._key.n)
        return value.to_bytes(k, "big")

    # ------------------------------------------------------------------
    def decrypt(self, ciphertext):
        k = self._size()
        h_len = self._hash.digest_size
        if len(ciphertext) != k or k < 2 * h_len + 2:
            raise ValueError("Ciphertext with incorrect length.")

        value = pow(int.from_bytes(ciphertext, "big"), self._key.d, self._key.n)
        em = value.to_bytes(k, "big")

        l_hash = self._hash.new(self._label).digest()
        y = em[0]
        masked_seed = em[1:1 + h_len]
        masked_db = em[1 + h_len:]
        seed = _xor(masked_seed, self._mgf(masked_db, h_len))
        db = _xor(masked_db, self._mgf(seed, k - h_len - 1))

        # one branch for every failure, so a wrong key cannot be told apart
        # from wrong padding by the error message
        failed = (y != 0) or (db[:h_len] != l_hash)
        index = h_len
        while index < len(db) and db[index] == 0:
            index += 1
        if index == len(db) or db[index] != 1:
            failed = True
        if failed:
            raise ValueError("Incorrect decryption.")
        return db[index + 1:]


def build_module():
    import types
    module = types.ModuleType("Crypto.Cipher.PKCS1_OAEP")
    module.new = lambda key, hashAlgo=None, mgfunc=None, label=b"", randfunc=None: \
        PKCS1OAEPCipher(key, hashAlgo, mgfunc, label, randfunc)
    module.PKCS1OAEP_Cipher = PKCS1OAEPCipher
    return module
