"""
Stand-ins for Crypto.Hash.*, Crypto.Util.strxor and Crypto.Util._cpu_features.

The hashes themselves come from Python's own hashlib, which is part of the
interpreter and therefore never blocked. Only the pycryptodome WRAPPER around
them is replaced, with the same attribute surface the rest of pycryptodome
expects - in particular the DigestInfo `oid`, which pkcs1_15 needs to build a
PKCS#1 v1.5 signature.
"""

import hashlib
import hmac as _stdlib_hmac
import types

# name -> (hashlib algorithm, DigestInfo OID)
HASH_SPECS = {
    "MD5": ("md5", "1.2.840.113549.2.5"),
    "SHA1": ("sha1", "1.3.14.3.2.26"),
    "SHA224": ("sha224", "2.16.840.1.101.3.4.2.4"),
    "SHA256": ("sha256", "2.16.840.1.101.3.4.2.1"),
    "SHA384": ("sha384", "2.16.840.1.101.3.4.2.2"),
    "SHA512": ("sha512", "2.16.840.1.101.3.4.2.3"),
    "SHA3_224": ("sha3_224", "2.16.840.1.101.3.4.2.7"),
    "SHA3_256": ("sha3_256", "2.16.840.1.101.3.4.2.8"),
    "SHA3_384": ("sha3_384", "2.16.840.1.101.3.4.2.9"),
    "SHA3_512": ("sha3_512", "2.16.840.1.101.3.4.2.10"),
}

SHAKE_SPECS = {"SHAKE128": "shake_128", "SHAKE256": "shake_256"}


class PureHash:
    def __init__(self, algo, oid, data=b""):
        self._algo = algo
        self.oid = oid
        self._h = hashlib.new(algo)
        self.digest_size = self._h.digest_size
        self.block_size = self._h.block_size
        if data:
            self.update(data)

    def update(self, data):
        self._h.update(data)
        return self

    def digest(self):
        return self._h.digest()

    def hexdigest(self):
        return self._h.hexdigest()

    def copy(self):
        clone = PureHash.__new__(PureHash)
        clone._algo, clone.oid = self._algo, self.oid
        clone._h = self._h.copy()
        clone.digest_size, clone.block_size = self.digest_size, self.block_size
        return clone

    def new(self, data=b""):
        return PureHash(self._algo, self.oid, data)


class PureShake:
    def __init__(self, algo, data=b""):
        self._algo = algo
        self._h = hashlib.new(algo)
        if data:
            self.update(data)

    def update(self, data):
        self._h.update(data)
        return self

    def read(self, length):
        return self._h.digest(length)

    def new(self, data=b""):
        return PureShake(self._algo, data)


class PureHMAC:
    def __init__(self, key, msg=b"", digestmod=None):
        algo = getattr(digestmod, "_hashlib_name", None) or "sha256"
        self._algo = algo
        self._h = _stdlib_hmac.new(key, msg, getattr(hashlib, algo))
        self._key = key
        self.digest_size = self._h.digest_size
        self.block_size = self._h.block_size
        self.oid = None

    def update(self, data):
        self._h.update(data)
        return self

    def digest(self):
        return self._h.digest()

    def hexdigest(self):
        return self._h.hexdigest()

    def copy(self):
        clone = PureHMAC.__new__(PureHMAC)
        clone._algo, clone._key = self._algo, self._key
        clone._h = self._h.copy()
        clone.digest_size, clone.block_size = self.digest_size, self.block_size
        clone.oid = None
        return clone

    def verify(self, mac_tag):
        if not _stdlib_hmac.compare_digest(self.digest(), bytes(mac_tag)):
            raise ValueError("MAC check failed")

    def hexverify(self, hex_mac_tag):
        self.verify(bytes.fromhex(hex_mac_tag))

    def new(self, key=None, msg=b"", digestmod=None):
        return PureHMAC(key if key is not None else self._key, msg,
                        digestmod or types.SimpleNamespace(_hashlib_name=self._algo))


def build_hash_modules():
    """Returns {module name: module} for every Crypto.Hash.* stand-in."""
    modules = {}
    for name, (algo, oid) in HASH_SPECS.items():
        probe = hashlib.new(algo)
        module = types.ModuleType("Crypto.Hash." + name)
        module.new = (lambda a=algo, o=oid: lambda data=b"", **kw: PureHash(a, o, data))()
        module.digest_size = probe.digest_size
        module.block_size = probe.block_size
        module.oid = oid
        module._hashlib_name = algo
        modules[name] = module

    for name, algo in SHAKE_SPECS.items():
        module = types.ModuleType("Crypto.Hash." + name)
        module.new = (lambda a=algo: lambda data=b"", **kw: PureShake(a, data))()
        module._hashlib_name = algo
        modules[name] = module

    hmac_module = types.ModuleType("Crypto.Hash.HMAC")
    hmac_module.new = lambda key, msg=b"", digestmod=None: PureHMAC(key, msg, digestmod)
    hmac_module.HMAC = PureHMAC
    modules["HMAC"] = hmac_module

    cmac_module = types.ModuleType("Crypto.Hash.CMAC")
    cmac_module.new = _cmac_new
    cmac_module.CMAC = PureCMAC
    modules["CMAC"] = cmac_module
    return modules


class PureCMAC:
    """AES-CMAC, the same OMAC1 used by EAX mode."""

    def __init__(self, key, msg=b"", ciphermod=None, mac_len=None, **kwargs):
        import _pure_modes
        if ciphermod is None or not hasattr(ciphermod, "_core_factory"):
            from Crypto.Cipher import AES as ciphermod
        self._core = ciphermod._core_factory(key)
        self._cmac = _pure_modes.cmac
        self.digest_size = mac_len or self._core.block_size
        self.block_size = self._core.block_size
        self.oid = None
        self._data = bytes(msg)

    def update(self, data):
        self._data += data
        return self

    def digest(self):
        return self._cmac(self._core, self._data)[:self.digest_size]

    def hexdigest(self):
        return self.digest().hex()

    def copy(self):
        clone = PureCMAC.__new__(PureCMAC)
        clone.__dict__.update(self.__dict__)
        clone._data = self._data
        return clone

    def verify(self, mac_tag):
        if not _stdlib_hmac.compare_digest(self.digest(), bytes(mac_tag)):
            raise ValueError("MAC check failed")

    def hexverify(self, hex_mac_tag):
        self.verify(bytes.fromhex(hex_mac_tag))


def _cmac_new(key, msg=b"", ciphermod=None, mac_len=None, **kwargs):
    return PureCMAC(key, msg, ciphermod, mac_len, **kwargs)


def build_strxor_module():
    module = types.ModuleType("Crypto.Util.strxor")

    def strxor(term1, term2, output=None):
        if len(term1) != len(term2):
            raise ValueError("Only byte strings of equal length can be xored")
        result = bytes(a ^ b for a, b in zip(term1, term2))
        if output is not None:
            output[:] = result
            return None
        return result

    def strxor_c(term, c, output=None):
        if not 0 <= c < 256:
            raise ValueError("c must be in range(256)")
        result = bytes(b ^ c for b in term)
        if output is not None:
            output[:] = result
            return None
        return result

    module.strxor = strxor
    module.strxor_c = strxor_c
    return module


def build_cpu_features_module():
    """Report no CPU acceleration at all, so pycryptodome never reaches for
    an AES-NI / BMI2 / ADX native helper. Any have_* query answers False,
    including ones added by a future pycryptodome release."""
    module = types.ModuleType("Crypto.Util._cpu_features")
    for name in ("have_aes_ni", "have_clmul", "have_bmi2", "have_adx",
                 "have_avx2", "have_sse2", "have_sha_ni"):
        setattr(module, name, lambda: False)
    module.available_cores = lambda: 1          # no thread pool in pure mode

    def __getattr__(name):
        if name.startswith("have_"):
            return lambda: False
        raise AttributeError(name)

    module.__getattr__ = __getattr__
    return module
