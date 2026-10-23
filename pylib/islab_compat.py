"""
islab_compat - make the Information Security Lab codebase run on a machine
that refuses to load pycryptodome's compiled modules.

WHY THIS EXISTS
    pycryptodome ships its ciphers and hashes as compiled .pyd / .so files.
    Some Windows machines run an Application Control policy (WDAC, or Smart
    App Control) that blocks unsigned native libraries, and the import fails
    with:

        OSError: Cannot load native module 'Crypto.Hash._SHA1':
                 ... error 0x11c7   (4551 - blocked by an Application
                 Control policy)

    Nothing can be installed to fix that, because the problem is not a
    missing package - it is the operating system refusing the binary.

WHAT IT DOES
    Most of pycryptodome is ordinary Python: the RSA key class, the ASN.1 and
    PEM code, PKCS#1 signing and padding, the prime generation in
    Crypto.Util.number. Only the ciphers, the hashes and a couple of helpers
    are native. So this module supplies pure-Python replacements for exactly
    those, registers them under their usual Crypto.* names, and lets the rest
    of the real library run on top.

    Replaced:  Crypto.Cipher.AES / DES / DES3 / PKCS1_OAEP
               Crypto.Hash.*  (backed by Python's own hashlib)
               Crypto.PublicKey.ECC, Crypto.Signature.DSS
               Crypto.Util.strxor, Crypto.Util._cpu_features
    Kept real: Crypto.PublicKey.RSA / DSA, Crypto.Signature.pkcs1_15 / pss,
               Crypto.Protocol.KDF, Crypto.IO.PEM, Crypto.Util.asn1,
               Crypto.Util.number, Crypto.Util.Padding, Crypto.Random

USE
    import islab_compat            # does nothing if pycryptodome works fine

    Or explicitly:
        islab_compat.ensure()      -> "native" or "pure"
        islab_compat.status()      -> a one-line description

    Set ISLAB_FORCE_PURE=1 in the environment to use the pure path even on a
    machine where the native modules load. That is how it gets tested.

WHAT IS COVERED
    Everything in Labs 1-8: AES-128/192/256, DES, 3DES, ECB/CBC/CFB/OFB/CTR
    and GCM, RSA (keygen, PEM, OAEP, PKCS#1 v1.5 and PSS signatures), DSA,
    ECC on P-256/P-384/P-521 with ECDSA, ElGamal, Schnorr, Paillier, Rabin,
    Diffie-Hellman, every hash, HMAC, PBKDF2, HKDF, searchable encryption
    and threshold decryption.

    Not covered: scrypt and CMAC, which nothing in this codebase uses. They
    raise a clear NotImplementedError if called.
"""

import os
import sys

MODE = None                     # "native" or "pure", set by ensure()


def _native_works():
    """True when pycryptodome's compiled modules load on this machine."""
    if os.environ.get("ISLAB_FORCE_PURE") == "1":
        return False
    try:
        import Crypto.Cipher.AES                            # noqa: F401
        import Crypto.Hash.SHA256                           # noqa: F401
        return True
    except Exception:
        return False


def _install_pure():
    """Inject the pure-Python replacements under their usual Crypto.* names.

    The real pycryptodome packages are imported first - their __init__ files
    are ordinary Python and load fine - so everything we do NOT replace keeps
    loading from disk as normal. We then overwrite just the native-backed
    leaves in sys.modules, and sys.modules is what `import` consults first.
    """
    import importlib

    import _pure_aes
    import _pure_des
    import _pure_hash
    import _pure_modes
    import _pure_ecc
    import _pure_oaep

    _guard_raw_api()

    parents = {}
    for name in ["Crypto", "Crypto.Cipher", "Crypto.Hash", "Crypto.Util",
                 "Crypto.PublicKey", "Crypto.Signature"]:
        parents[name] = importlib.import_module(name)

    replacements = {}

    aes = _pure_modes.make_module("AES", _pure_aes.AESCore, (16, 24, 32), 16)
    des = _pure_modes.make_module("DES", _pure_des.DESCore, (8,), 8)
    des3 = _pure_modes.make_module("DES3", _pure_des.DES3Core, (16, 24), 8)
    des3.adjust_key_parity = _pure_des.adjust_key_parity
    for short, module in (("AES", aes), ("DES", des), ("DES3", des3)):
        replacements["Crypto.Cipher." + short] = module

    replacements["Crypto.Cipher.PKCS1_OAEP"] = _pure_oaep.build_module()

    for short, module in _pure_hash.build_hash_modules().items():
        replacements["Crypto.Hash." + short] = module

    for module in (_pure_hash.build_strxor_module(),
                   _pure_hash.build_cpu_features_module()):
        replacements[module.__name__] = module

    # elliptic curves have no pure fallback inside pycryptodome at all, so
    # ECC and DSS are replaced outright (DSS still handles real DSA keys)
    replacements.update(_pure_ecc.build_modules())

    for full_name, module in replacements.items():
        sys.modules.pop(full_name, None)        # drop any half-loaded native one
        sys.modules[full_name] = module
        parent_name, _, short = full_name.rpartition(".")
        setattr(parents[parent_name], short, module)


def _guard_raw_api():
    """Stop a blocked native library from breaking an IMPORT.

    Several pure-Python pycryptodome modules call load_pycryptodome_raw_lib()
    at module level for a primitive they may never use - Crypto.Protocol.KDF
    loads the scrypt core, and Crypto.IO.PEM imports KDF, so one blocked
    library takes PEM, PKCS8 and DSA down with it.

    This wrapper hands back a placeholder for exactly those libraries, named
    in STUBBABLE below. Everything else keeps raising OSError, because
    pycryptodome catches OSError itself to fall back to its own pure-Python
    code - Crypto.Math.Numbers does this to choose IntegerNat over the GMP
    and _modexp backends - and swallowing that would break the fallback we
    are relying on.
    """
    import Crypto.Util._raw_api as raw_api

    if getattr(raw_api, "_islab_guarded", False):
        return
    original = raw_api.load_pycryptodome_raw_lib

    # no pure fallback inside pycryptodome, and nothing in this codebase
    # calls into them: scrypt (imported by KDF, and so by PEM and DSA) and
    # the constant-time PKCS#1 decoder (we supply our own OAEP instead)
    STUBBABLE = ("Crypto.Protocol._scrypt", "Crypto.Cipher._pkcs1_decode")

    class _Unavailable:
        def __init__(self, name):
            self._name = name

        def __getattr__(self, item):
            def refuse(*args, **kwargs):
                raise NotImplementedError(
                    "%s.%s needs the native module '%s', which this machine "
                    "blocks. The pure-Python fallback does not provide it."
                    % (self._name, item, self._name))
            return refuse

    def guarded(name, cdecl, *args, **kwargs):
        try:
            return original(name, cdecl, *args, **kwargs)
        except OSError:
            if name in STUBBABLE:
                return _Unavailable(name)
            raise

    raw_api.load_pycryptodome_raw_lib = guarded
    raw_api._islab_guarded = True


def ensure():
    """Pick the backend once. Returns 'native' or 'pure'."""
    global MODE
    if MODE is None:
        if _native_works():
            MODE = "native"
        else:
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            _install_pure()
            MODE = "pure"
    return MODE


def status():
    mode = ensure()
    if mode == "native":
        return "pycryptodome native modules: OK"
    return ("pycryptodome native modules are blocked on this machine - "
            "using the pure-Python fallback")


ensure()
