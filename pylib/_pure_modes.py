"""
Mode-of-operation wrappers with the same surface as pycryptodome's cipher
objects: new(), .encrypt(), .decrypt(), .iv, .nonce, .block_size, and the
AEAD calls for GCM.

Mode numbers are pycryptodome's own, so code that compares them still works.
"""

import os

MODE_ECB = 1
MODE_CBC = 2
MODE_CFB = 3
MODE_OFB = 5
MODE_CTR = 6
MODE_EAX = 9
MODE_GCM = 11

_MODE_NAMES = {MODE_ECB: "ECB", MODE_CBC: "CBC", MODE_CFB: "CFB",
               MODE_OFB: "OFB", MODE_CTR: "CTR", MODE_EAX: "EAX",
               MODE_GCM: "GCM"}


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def _inc(counter_bytes):
    value = int.from_bytes(counter_bytes, "big") + 1
    return (value % (1 << (8 * len(counter_bytes)))).to_bytes(len(counter_bytes), "big")


class _Cipher:
    def __init__(self, core, mode, iv=None, nonce=None, segment_size=8,
                 initial_value=0, mac_len=16):
        self._core = core
        self.block_size = core.block_size
        self.mode = mode
        bs = self.block_size

        if mode in (MODE_CBC, MODE_CFB, MODE_OFB):
            if iv is None:
                iv = os.urandom(bs)
            if len(iv) != bs:
                raise ValueError("Incorrect IV length (it must be %d bytes long)" % bs)
            self.iv = self.IV = bytes(iv)
            self._chain = bytes(iv)
        elif mode == MODE_CTR:
            if nonce is None:
                nonce = os.urandom(bs // 2)
            self.nonce = bytes(nonce)
            if len(self.nonce) >= bs:
                raise ValueError("Nonce is too long")
            self._ctr_len = bs - len(self.nonce)
            self._counter = (initial_value % (1 << (8 * self._ctr_len))).to_bytes(
                self._ctr_len, "big")
            self._keystream = b""
        elif mode == MODE_EAX:
            if nonce is None:
                nonce = os.urandom(bs)
            self.nonce = bytes(nonce)
            self._mac_len = mac_len
            self._n = _omac(self._core, 0, self.nonce)
            self._counter = self._n
            self._keystream = b""
            self._aad = b""
            self._ct = b""
        elif mode == MODE_GCM:
            if nonce is None:
                nonce = os.urandom(16)
            if len(nonce) == 0:
                raise ValueError("Nonce cannot be empty")
            self.nonce = bytes(nonce)
            self._mac_len = mac_len
            self._gcm_setup()
        elif mode != MODE_ECB:
            raise ValueError("mode %r is not supported by the pure-Python fallback" % mode)

        if mode == MODE_CFB:
            if segment_size % 8:
                raise ValueError("segment_size must be a multiple of 8 bits")
            self._segment = segment_size // 8
            self.segment_size = segment_size
        self._stream = b""

    # ------------------------------------------------------------------ ECB
    def _ecb(self, data, encrypt):
        bs = self.block_size
        if len(data) % bs:
            raise ValueError("Data must be padded to %d byte boundary in ECB mode" % bs)
        work = self._core.encrypt_block if encrypt else self._core.decrypt_block
        return b"".join(work(data[i:i + bs]) for i in range(0, len(data), bs))

    # ------------------------------------------------------------------ CBC
    def _cbc(self, data, encrypt):
        bs = self.block_size
        if len(data) % bs:
            raise ValueError("Data must be padded to %d byte boundary in CBC mode" % bs)
        out = []
        for i in range(0, len(data), bs):
            block = data[i:i + bs]
            if encrypt:
                cipher = self._core.encrypt_block(_xor(block, self._chain))
                out.append(cipher)
                self._chain = cipher
            else:
                out.append(_xor(self._core.decrypt_block(block), self._chain))
                self._chain = block
        return b"".join(out)

    # ------------------------------------------------------------------ CFB
    def _cfb(self, data, encrypt):
        bs = self.block_size
        size = self._segment
        out = bytearray()
        position = 0
        while position < len(data):
            chunk = data[position:position + size]
            keystream = self._core.encrypt_block(self._chain)[:len(chunk)]
            result = _xor(chunk, keystream)
            feed = result if encrypt else chunk
            if len(feed) < size:                       # final short segment
                self._chain = self._chain[len(feed):] + feed
            else:
                self._chain = self._chain[size:] + feed
            self._chain = self._chain[-bs:]
            out += result
            position += size
        return bytes(out)

    # ------------------------------------------------------------------ OFB
    def _ofb(self, data):
        out = bytearray()
        position = 0
        while position < len(data):
            self._chain = self._core.encrypt_block(self._chain)
            chunk = data[position:position + self.block_size]
            out += _xor(chunk, self._chain[:len(chunk)])
            position += self.block_size
        return bytes(out)

    # ------------------------------------------------------------------ CTR
    def _ctr(self, data):
        out = bytearray()
        position = 0
        while position < len(data):
            if not self._keystream:
                self._keystream = self._core.encrypt_block(self.nonce + self._counter)
                self._counter = _inc(self._counter)
            take = min(len(self._keystream), len(data) - position)
            out += _xor(data[position:position + take], self._keystream[:take])
            self._keystream = self._keystream[take:]
            position += take
        return bytes(out)

    # ------------------------------------------------------------------ GCM
    def _gcm_setup(self):
        self._h = int.from_bytes(self._core.encrypt_block(b"\x00" * 16), "big")
        if len(self.nonce) == 12:
            self._j0 = self.nonce + b"\x00\x00\x00\x01"
        else:
            padded = self.nonce + b"\x00" * ((16 - len(self.nonce) % 16) % 16)
            value = self._ghash(padded + b"\x00" * 8
                                + (len(self.nonce) * 8).to_bytes(8, "big"))
            self._j0 = value
        self._aad = b""
        self._ct = b""
        self._counter = _inc(self._j0)
        self._keystream = b""
        self._done = False

    def _ghash(self, data, start=0):
        y = start
        for i in range(0, len(data), 16):
            block = data[i:i + 16]
            y ^= int.from_bytes(block + b"\x00" * (16 - len(block)), "big")
            y = _gf128(y, self._h)
        return y.to_bytes(16, "big")

    def update(self, data):
        self._aad += data
        return self

    def _gcm_stream(self, data):
        out = bytearray()
        position = 0
        while position < len(data):
            if not self._keystream:
                self._keystream = self._core.encrypt_block(self._counter)
                self._counter = _inc(self._counter)
            take = min(len(self._keystream), len(data) - position)
            out += _xor(data[position:position + take], self._keystream[:take])
            self._keystream = self._keystream[take:]
            position += take
        return bytes(out)

    def _eax_stream(self, data):
        out = bytearray()
        position = 0
        while position < len(data):
            if not self._keystream:
                self._keystream = self._core.encrypt_block(self._counter)
                self._counter = _inc(self._counter)
            take = min(len(self._keystream), len(data) - position)
            out += _xor(data[position:position + take], self._keystream[:take])
            self._keystream = self._keystream[take:]
            position += take
        return bytes(out)

    def _eax_tag(self):
        header = _omac(self._core, 1, self._aad)
        body = _omac(self._core, 2, self._ct)
        tag = _xor(_xor(self._n, header), body)
        return tag[:self._mac_len]

    def _gcm_tag(self):
        aad, ct = self._aad, self._ct
        padded_aad = aad + b"\x00" * ((16 - len(aad) % 16) % 16)
        padded_ct = ct + b"\x00" * ((16 - len(ct) % 16) % 16)
        lengths = (len(aad) * 8).to_bytes(8, "big") + (len(ct) * 8).to_bytes(8, "big")
        s = self._ghash(padded_aad + padded_ct + lengths)
        return _xor(s, self._core.encrypt_block(self._j0))[:self._mac_len]

    # -------------------------------------------------------------- public
    def encrypt(self, data):
        if self.mode == MODE_ECB:
            return self._ecb(data, True)
        if self.mode == MODE_CBC:
            return self._cbc(data, True)
        if self.mode == MODE_CFB:
            return self._cfb(data, True)
        if self.mode == MODE_OFB:
            return self._ofb(data)
        if self.mode == MODE_CTR:
            return self._ctr(data)
        if self.mode == MODE_EAX:
            out = self._eax_stream(data)
            self._ct += out
            return out
        if self.mode == MODE_GCM:
            out = self._gcm_stream(data)
            self._ct += out
            return out
        raise ValueError("unsupported mode")

    def decrypt(self, data):
        if self.mode == MODE_ECB:
            return self._ecb(data, False)
        if self.mode == MODE_CBC:
            return self._cbc(data, False)
        if self.mode == MODE_CFB:
            return self._cfb(data, False)
        if self.mode == MODE_OFB:
            return self._ofb(data)
        if self.mode == MODE_CTR:
            return self._ctr(data)
        if self.mode == MODE_EAX:
            self._ct += data
            return self._eax_stream(data)
        if self.mode == MODE_GCM:
            self._ct += data
            return self._gcm_stream(data)
        raise ValueError("unsupported mode")

    def digest(self):
        return self._eax_tag() if self.mode == MODE_EAX else self._gcm_tag()

    def hexdigest(self):
        return self.digest().hex()

    def verify(self, received):
        import hmac as _hmac
        expected = self._eax_tag() if self.mode == MODE_EAX else self._gcm_tag()
        if not _hmac.compare_digest(expected, bytes(received)):
            raise ValueError("MAC check failed")

    def hexverify(self, received):
        self.verify(bytes.fromhex(received))

    def encrypt_and_digest(self, data):
        return self.encrypt(data), self.digest()

    def decrypt_and_verify(self, data, received):
        plain = self.decrypt(data)
        self.verify(received)
        return plain


def _dbl(block, rb):
    """Double a block in GF(2^n): shift left one bit, xor Rb on overflow."""
    value = int.from_bytes(block, "big")
    size = len(block) * 8
    carry = value >> (size - 1)
    value = ((value << 1) & ((1 << size) - 1)) ^ (rb if carry else 0)
    return value.to_bytes(len(block), "big")


def cmac(core, data):
    """AES-CMAC / OMAC1 (RFC 4493, generalised to any block size)."""
    bs = core.block_size
    rb = 0x87 if bs == 16 else 0x1B                 # 128-bit / 64-bit constants
    l = core.encrypt_block(b"\x00" * bs)
    k1 = _dbl(l, rb)
    k2 = _dbl(k1, rb)

    complete = len(data) > 0 and len(data) % bs == 0
    if complete:
        blocks = [data[i:i + bs] for i in range(0, len(data), bs)]
        last = _xor(blocks[-1], k1)
    else:
        padded = data + b"\x80" + b"\x00" * (bs - 1 - len(data) % bs)
        blocks = [padded[i:i + bs] for i in range(0, len(padded), bs)]
        last = _xor(blocks[-1], k2)

    chain = b"\x00" * bs
    for block in blocks[:-1]:
        chain = core.encrypt_block(_xor(chain, block))
    return core.encrypt_block(_xor(chain, last))


def _omac(core, tag, data):
    """OMAC^t from the EAX construction: CMAC over [t] || data."""
    return cmac(core, b"\x00" * (core.block_size - 1) + bytes([tag]) + data)


def _gf128(x, y):
    """Multiplication in GF(2^128) with GCM's bit ordering."""
    reduction = 0xE1 << 120
    z = 0
    v = y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ reduction
        else:
            v >>= 1
    return z


def make_module(name, core_factory, key_sizes, block_size):
    """Builds a module object that looks like Crypto.Cipher.<name>."""
    import types
    module = types.ModuleType("Crypto.Cipher." + name)

    def new(key, mode=MODE_ECB, *args, **kwargs):
        iv = kwargs.pop("iv", None)
        if iv is None and args and mode in (MODE_CBC, MODE_CFB, MODE_OFB):
            iv = args[0]
        if iv is None:
            iv = kwargs.pop("IV", None)
        return _Cipher(core_factory(key), mode, iv=iv,
                       nonce=kwargs.pop("nonce", None),
                       segment_size=kwargs.pop("segment_size", 8),
                       initial_value=kwargs.pop("initial_value", 0),
                       mac_len=kwargs.pop("mac_len", 16))

    module.new = new
    module.block_size = block_size
    module.key_size = key_sizes
    module.MODE_ECB = MODE_ECB
    module.MODE_CBC = MODE_CBC
    module.MODE_CFB = MODE_CFB
    module.MODE_OFB = MODE_OFB
    module.MODE_CTR = MODE_CTR
    module.MODE_EAX = MODE_EAX
    module.MODE_GCM = MODE_GCM
    module._core_factory = core_factory          # used by Crypto.Hash.CMAC
    return module
