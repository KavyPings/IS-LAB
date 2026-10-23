"""
Pure-Python elliptic curves (NIST P-256 / P-384 / P-521) plus ECDSA and DSA,
standing in for Crypto.PublicKey.ECC and Crypto.Signature.DSS.

pycryptodome implements its curve arithmetic entirely in a native module with
no pure fallback, so this is a replacement rather than a patch. Keys are
written and read as the same PKCS#8 / SubjectPublicKeyInfo PEM that
pycryptodome produces, so a key file made on a machine with working native
modules still loads here, and the other way round.

DER encoding is done with Crypto.Util.asn1, which is ordinary Python and
always available.
"""

import os

CURVES = {
    "NIST P-256": {
        "names": ("p256", "P-256", "prime256v1", "secp256r1", "NIST P-256"),
        "oid": "1.2.840.10045.3.1.7",
        "p": 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
        "a": -3,
        "b": 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
        "Gx": 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
        "Gy": 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
        "n": 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
    },
    "NIST P-384": {
        "names": ("p384", "P-384", "secp384r1", "NIST P-384"),
        "oid": "1.3.132.0.34",
        "p": int("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"
                 "ffffffff0000000000000000ffffffff", 16),
        "a": -3,
        "b": int("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a"
                 "c656398d8a2ed19d2a85c8edd3ec2aef", 16),
        "Gx": int("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38"
                  "5502f25dbf55296c3a545e3872760ab7", 16),
        "Gy": int("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c0"
                  "0a60b1ce1d7e819d7a431d7c90ea0e5f", 16),
        "n": int("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf"
                 "581a0db248b0a77aecec196accc52973", 16),
    },
    "NIST P-521": {
        "names": ("p521", "P-521", "secp521r1", "NIST P-521"),
        "oid": "1.3.132.0.35",
        "p": (1 << 521) - 1,
        "a": -3,
        "b": int("0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef1"
                 "09e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b50"
                 "3f00", 16),
        "Gx": int("00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d"
                  "3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e"
                  "5bd66", 16),
        "Gy": int("011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e"
                  "662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd"
                  "16650", 16),
        "n": int("01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                 "ffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386"
                 "409", 16),
    },
}


def _find_curve(name):
    for canonical, data in CURVES.items():
        if str(name) in data["names"] or str(name) == canonical:
            return canonical, data
    raise ValueError("Unsupported curve %r in the pure-Python fallback" % (name,))


def _by_oid(oid):
    for canonical, data in CURVES.items():
        if data["oid"] == oid:
            return canonical, data
    raise ValueError("Unsupported curve OID %s" % oid)


class EccPoint:
    """An affine point. Arithmetic runs in Jacobian coordinates internally."""

    def __init__(self, x, y, curve="NIST P-256"):
        self._name, self._curve = _find_curve(curve)
        self._x = None if x is None else int(x) % self._curve["p"]
        self._y = None if y is None else int(y) % self._curve["p"]
        if x is not None and not self._on_curve():
            raise ValueError("The point is not on the curve")

    # ---------------------------------------------------------------- basics
    @property
    def x(self):
        if self._x is None:
            raise ValueError("The point at infinity has no coordinates")
        return self._x

    @property
    def y(self):
        if self._y is None:
            raise ValueError("The point at infinity has no coordinates")
        return self._y

    @property
    def xy(self):
        return (self.x, self.y)

    def size_in_bytes(self):
        return (self._curve["p"].bit_length() + 7) // 8

    def size_in_bits(self):
        return self._curve["p"].bit_length()

    def is_point_at_infinity(self):
        return self._x is None

    def copy(self):
        return EccPoint(self._x, self._y, self._name)

    def __eq__(self, other):
        return (isinstance(other, EccPoint) and self._name == other._name
                and self._x == other._x and self._y == other._y)

    def _on_curve(self):
        if self._x is None:
            return True
        p, a, b = self._curve["p"], self._curve["a"], self._curve["b"]
        return (self._y * self._y - self._x ** 3 - a * self._x - b) % p == 0

    # ------------------------------------------------------------ arithmetic
    def _to_jacobian(self):
        if self._x is None:
            return (1, 1, 0)
        return (self._x, self._y, 1)

    def _from_jacobian(self, point):
        p = self._curve["p"]
        x, y, z = point
        if z == 0:
            return EccPoint(None, None, self._name)
        inv = pow(z, -1, p)
        inv2 = inv * inv % p
        result = EccPoint.__new__(EccPoint)
        result._name, result._curve = self._name, self._curve
        result._x = x * inv2 % p
        result._y = y * inv2 % p * inv % p
        return result

    def _double_j(self, point):
        p, a = self._curve["p"], self._curve["a"]
        x, y, z = point
        if z == 0 or y == 0:
            return (1, 1, 0)
        ysq = y * y % p
        zsq = z * z % p
        s = 4 * x * ysq % p
        m = (3 * x * x + a * zsq * zsq) % p
        xr = (m * m - 2 * s) % p
        yr = (m * (s - xr) - 8 * ysq * ysq) % p
        zr = 2 * y * z % p
        return (xr, yr, zr)

    def _add_j(self, first, second):
        p = self._curve["p"]
        x1, y1, z1 = first
        x2, y2, z2 = second
        if z1 == 0:
            return second
        if z2 == 0:
            return first
        z1sq = z1 * z1 % p
        z2sq = z2 * z2 % p
        u1 = x1 * z2sq % p
        u2 = x2 * z1sq % p
        s1 = y1 * z2sq % p * z2 % p
        s2 = y2 * z1sq % p * z1 % p
        if u1 == u2:
            if s1 != s2:
                return (1, 1, 0)
            return self._double_j(first)
        h = (u2 - u1) % p
        r = (s2 - s1) % p
        hsq = h * h % p
        hcu = hsq * h % p
        xr = (r * r - hcu - 2 * u1 * hsq) % p
        yr = (r * (u1 * hsq - xr) - s1 * hcu) % p
        zr = h * z1 % p * z2 % p
        return (xr, yr, zr)

    def __add__(self, other):
        return self._from_jacobian(self._add_j(self._to_jacobian(), other._to_jacobian()))

    def __mul__(self, scalar):
        scalar = int(scalar)
        if scalar < 0:
            raise ValueError("Scalar must not be negative")
        result = (1, 1, 0)
        addend = self._to_jacobian()
        while scalar:
            if scalar & 1:
                result = self._add_j(result, addend)
            addend = self._double_j(addend)
            scalar >>= 1
        return self._from_jacobian(result)

    __rmul__ = __mul__

    def double(self):
        return self._from_jacobian(self._double_j(self._to_jacobian()))


def _generator(name):
    data = CURVES[name]
    return EccPoint(data["Gx"], data["Gy"], name)


class _CurveInfo:
    """Just enough of pycryptodome's curve object for the code in this lab."""

    def __init__(self, name):
        self.name = name
        data = CURVES[name]
        self.p = data["p"]
        self.order = data["n"]
        self.b = data["b"]
        self.oid = data["oid"]
        self.G = _generator(name)

    def __repr__(self):
        return "Curve(%s)" % self.name


class EccKey:
    def __init__(self, curve="NIST P-256", d=None, point=None):
        self._name, self._data = _find_curve(curve)
        self.curve = self._name
        self._curve = _CurveInfo(self._name)
        self._d = None if d is None else int(d)
        if point is None and self._d is not None:
            point = _generator(self._name) * self._d
        self._point = point

    @property
    def d(self):
        if self._d is None:
            raise ValueError("This is not a private ECC key")
        return self._d

    @property
    def pointQ(self):
        return self._point

    @property
    def public_key_point(self):
        return self._point

    def has_private(self):
        return self._d is not None

    def public_key(self):
        return EccKey(self._name, None, self._point)

    publickey = public_key

    def size_in_bytes(self):
        return (self._data["n"].bit_length() + 7) // 8

    def size_in_bits(self):
        return self._data["n"].bit_length()

    def __eq__(self, other):
        return (isinstance(other, EccKey) and self._name == other._name
                and self._point == other._point and self._d == other._d)

    # ---------------------------------------------------------- import/export
    def _point_bytes(self):
        size = self._point.size_in_bytes()
        return (b"\x04" + self._point.x.to_bytes(size, "big")
                + self._point.y.to_bytes(size, "big"))

    def export_key(self, **kwargs):
        from Crypto.IO import PEM
        from Crypto.Util.asn1 import (DerBitString, DerInteger, DerObjectId,
                                      DerOctetString, DerSequence)       # noqa: F401

        fmt = kwargs.get("format", "PEM")
        oid = DerObjectId(self._data["oid"])
        if self.has_private():
            size = self.size_in_bytes()
            # PKCS#8: version, AlgorithmIdentifier, then the RFC 5915 key
            ec_private = _der_ec_private(self._d, size, self._point_bytes())
            der = DerSequence([
                DerInteger(0),
                DerSequence([DerObjectId("1.2.840.10045.2.1"), oid]),
                DerOctetString(ec_private),
            ]).encode()
            marker = "PRIVATE KEY"
        else:
            der = DerSequence([
                DerSequence([DerObjectId("1.2.840.10045.2.1"), oid]),
                DerBitString(self._point_bytes()),
            ]).encode()
            marker = "PUBLIC KEY"
        if fmt == "DER":
            return der
        if fmt in ("PEM", "pem"):
            return PEM.encode(der, marker)
        raise ValueError("Unsupported ECC export format %r in the fallback" % fmt)


def _der_ec_private(d, size, point_bytes):
    """RFC 5915 ECPrivateKey, with the public key in the optional [1] field."""
    from Crypto.Util.asn1 import DerBitString, DerInteger, DerOctetString, DerSequence
    public = DerBitString(point_bytes)
    public_der = public.encode()
    tagged = b"\xa1" + _der_length(len(public_der)) + public_der
    body = (DerInteger(1).encode()
            + DerOctetString(d.to_bytes(size, "big")).encode()
            + tagged)
    return b"\x30" + _der_length(len(body)) + body


def _der_length(length):
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def generate(**kwargs):
    curve = kwargs.get("curve", "NIST P-256")
    randfunc = kwargs.get("randfunc", os.urandom)
    name, data = _find_curve(curve)
    order = data["n"]
    size = (order.bit_length() + 7) // 8
    while True:
        candidate = int.from_bytes(randfunc(size + 8), "big") % order
        if candidate != 0:
            return EccKey(name, candidate)


def construct(**kwargs):
    curve = kwargs.get("curve", "NIST P-256")
    name, _ = _find_curve(curve)
    if "d" in kwargs and kwargs["d"] is not None:
        return EccKey(name, kwargs["d"])
    point = EccPoint(kwargs["point_x"], kwargs["point_y"], name)
    return EccKey(name, None, point)


def import_key(encoded, passphrase=None, **kwargs):
    from Crypto.IO import PEM
    from Crypto.Util.asn1 import DerBitString, DerObjectId, DerOctetString, DerSequence

    if isinstance(encoded, str):
        der, _marker, _enc = PEM.decode(encoded, passphrase)
    elif encoded[:1] == b"-":
        der, _marker, _enc = PEM.decode(encoded.decode(), passphrase)
    else:
        der = bytes(encoded)

    outer = DerSequence().decode(der, nr_elements=(2, 3), only_ints_expected=False)

    # SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier, BIT STRING }
    if len(outer) == 2:
        algorithm = DerSequence().decode(outer[0], nr_elements=2,
                                         only_ints_expected=False)
        curve_oid = DerObjectId().decode(algorithm[1]).value
        name, _ = _by_oid(curve_oid)
        bits = DerBitString().decode(outer[1]).value
        return _key_from_point_bytes(bits, name)

    # PKCS#8: SEQUENCE { INTEGER 0, AlgorithmIdentifier, OCTET STRING }
    algorithm = DerSequence().decode(outer[1], nr_elements=2, only_ints_expected=False)
    curve_oid = DerObjectId().decode(algorithm[1]).value
    name, data = _by_oid(curve_oid)
    inner = DerOctetString().decode(outer[2]).payload
    ec_private = DerSequence().decode(inner, nr_elements=(2, 3, 4),
                                      only_ints_expected=False)
    secret = DerOctetString().decode(ec_private[1]).payload
    return EccKey(name, int.from_bytes(secret, "big"))


def _key_from_point_bytes(raw, name):
    if raw[:1] != b"\x04":
        raise ValueError("Only uncompressed ECC points are supported here")
    size = (CURVES[name]["p"].bit_length() + 7) // 8
    x = int.from_bytes(raw[1:1 + size], "big")
    y = int.from_bytes(raw[1 + size:1 + 2 * size], "big")
    return EccKey(name, None, EccPoint(x, y, name))


# ---------------------------------------------------------------------------
# ECDSA and DSA signing, the surface Crypto.Signature.DSS offers
# ---------------------------------------------------------------------------

def _truncate(digest, order_bits):
    value = int.from_bytes(digest, "big")
    extra = len(digest) * 8 - order_bits
    return value >> extra if extra > 0 else value


class _EcdsaSigScheme:
    def __init__(self, key, encoding="binary", randfunc=None):
        self._key = key
        self._encoding = encoding
        self._rand = randfunc or os.urandom
        self._order = CURVES[key.curve]["n"]
        self._size = (self._order.bit_length() + 7) // 8

    def can_sign(self):
        return self._key.has_private()

    def _random_scalar(self):
        while True:
            k = int.from_bytes(self._rand(self._size + 8), "big") % self._order
            if k != 0:
                return k

    def sign(self, msg_hash):
        if not self._key.has_private():
            raise TypeError("No private key available for signing")
        n = self._order
        z = _truncate(msg_hash.digest(), n.bit_length())
        while True:
            k = self._random_scalar()
            point = _generator(self._key.curve) * k
            r = point.x % n
            if r == 0:
                continue
            s = pow(k, -1, n) * (z + r * self._key.d) % n
            if s == 0:
                continue
            break
        return _encode_signature(r, s, self._size, self._encoding)

    def verify(self, msg_hash, signature):
        n = self._order
        r, s = _decode_signature(signature, self._size, self._encoding)
        if not (0 < r < n and 0 < s < n):
            raise ValueError("The signature is not authentic")
        z = _truncate(msg_hash.digest(), n.bit_length())
        w = pow(s, -1, n)
        point = (_generator(self._key.curve) * (z * w % n)
                 + self._key.pointQ * (r * w % n))
        if point.is_point_at_infinity() or point.x % n != r:
            raise ValueError("The signature is not authentic")
        return True


class _DsaSigScheme:
    """Plain DSA, for the real pycryptodome DSA key object."""

    def __init__(self, key, encoding="binary", randfunc=None):
        self._key = key
        self._encoding = encoding
        self._rand = randfunc or os.urandom
        self._q = int(key.q)
        self._size = (self._q.bit_length() + 7) // 8

    def can_sign(self):
        return self._key.has_private()

    def sign(self, msg_hash):
        p, q, g, x = int(self._key.p), self._q, int(self._key.g), int(self._key.x)
        z = _truncate(msg_hash.digest(), q.bit_length())
        while True:
            k = int.from_bytes(self._rand(self._size + 8), "big") % q
            if k == 0:
                continue
            r = pow(g, k, p) % q
            if r == 0:
                continue
            s = pow(k, -1, q) * (z + x * r) % q
            if s == 0:
                continue
            return _encode_signature(r, s, self._size, self._encoding)

    def verify(self, msg_hash, signature):
        p, q, g, y = int(self._key.p), self._q, int(self._key.g), int(self._key.y)
        r, s = _decode_signature(signature, self._size, self._encoding)
        if not (0 < r < q and 0 < s < q):
            raise ValueError("The signature is not authentic")
        z = _truncate(msg_hash.digest(), q.bit_length())
        w = pow(s, -1, q)
        v = (pow(g, z * w % q, p) * pow(y, r * w % q, p)) % p % q
        if v != r:
            raise ValueError("The signature is not authentic")
        return True


def _encode_signature(r, s, size, encoding):
    if encoding == "der":
        from Crypto.Util.asn1 import DerInteger, DerSequence
        return DerSequence([DerInteger(r), DerInteger(s)]).encode()
    return r.to_bytes(size, "big") + s.to_bytes(size, "big")


def _decode_signature(signature, size, encoding):
    signature = bytes(signature)
    if encoding == "der":
        from Crypto.Util.asn1 import DerSequence
        parts = DerSequence().decode(signature)
        return int(parts[0]), int(parts[1])
    if len(signature) != 2 * size:
        raise ValueError("The signature is not authentic")
    return (int.from_bytes(signature[:size], "big"),
            int.from_bytes(signature[size:], "big"))


def dss_new(key, mode, encoding="binary", randfunc=None):
    if mode not in ("fips-186-3", "deterministic-rfc6979"):
        raise ValueError("Unknown DSS mode %r" % mode)
    if isinstance(key, EccKey):
        return _EcdsaSigScheme(key, encoding, randfunc)
    if hasattr(key, "q"):
        return _DsaSigScheme(key, encoding, randfunc)
    raise ValueError("DSS needs a DSA or ECC key")


def build_modules():
    import types
    ecc = types.ModuleType("Crypto.PublicKey.ECC")
    ecc.generate = generate
    ecc.construct = construct
    ecc.import_key = import_key
    ecc.EccKey = EccKey
    ecc.EccPoint = EccPoint
    ecc._curves = {name: _CurveInfo(name) for name in CURVES}

    dss = types.ModuleType("Crypto.Signature.DSS")
    dss.new = dss_new
    return {"Crypto.PublicKey.ECC": ecc, "Crypto.Signature.DSS": dss}
