"""
Pure-Python AES (FIPS-197), used only when this machine refuses to load
pycryptodome's compiled modules.

The tables are COMPUTED from the algebraic definition rather than typed out,
so there is nothing to mistype: the S-box is the multiplicative inverse in
GF(2^8) followed by the standard affine transform.
"""

BLOCK_SIZE = 16


def _gmul(a, b):
    """Multiply two bytes in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1."""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        high = a & 0x80
        a = (a << 1) & 0xFF
        if high:
            a ^= 0x1B
        b >>= 1
    return result


def _build_tables():
    exp, log = [0] * 512, [0] * 256
    x = 1
    for i in range(255):
        exp[i] = x
        log[x] = i
        x = _gmul(x, 3)                 # 3 generates the whole field
    for i in range(255, 512):
        exp[i] = exp[i - 255]

    def rotl8(value, shift):
        return ((value << shift) | (value >> (8 - shift))) & 0xFF

    sbox = [0] * 256
    sbox[0] = 0x63
    for a in range(1, 256):
        inverse = exp[255 - log[a]]
        sbox[a] = (inverse ^ rotl8(inverse, 1) ^ rotl8(inverse, 2)
                   ^ rotl8(inverse, 3) ^ rotl8(inverse, 4) ^ 0x63) & 0xFF

    inv_sbox = [0] * 256
    for a, value in enumerate(sbox):
        inv_sbox[value] = a
    return sbox, inv_sbox


SBOX, INV_SBOX = _build_tables()
RCON = [0x01]
for _i in range(1, 14):
    RCON.append(_gmul(RCON[-1], 2))

# multiplication by the four constants MixColumns needs, precomputed
MUL = {c: [_gmul(x, c) for x in range(256)] for c in (1, 2, 3, 9, 11, 13, 14)}


def _expand_key(key):
    """Returns the round keys as a flat list of 4-byte words."""
    nk = len(key) // 4                  # 4, 6 or 8
    nr = nk + 6                         # 10, 12 or 14 rounds
    words = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        temp = list(words[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]                      # RotWord
            temp = [SBOX[b] for b in temp]                  # SubWord
            temp[0] ^= RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            temp = [SBOX[b] for b in temp]
        words.append([words[i - nk][j] ^ temp[j] for j in range(4)])
    return words, nr


def _add_round_key(state, words, round_number):
    for c in range(4):
        word = words[round_number * 4 + c]
        for r in range(4):
            state[r][c] ^= word[r]


def _mix_columns(state):
    for c in range(4):
        a0, a1, a2, a3 = state[0][c], state[1][c], state[2][c], state[3][c]
        state[0][c] = MUL[2][a0] ^ MUL[3][a1] ^ a2 ^ a3
        state[1][c] = a0 ^ MUL[2][a1] ^ MUL[3][a2] ^ a3
        state[2][c] = a0 ^ a1 ^ MUL[2][a2] ^ MUL[3][a3]
        state[3][c] = MUL[3][a0] ^ a1 ^ a2 ^ MUL[2][a3]


def _inv_mix_columns(state):
    for c in range(4):
        a0, a1, a2, a3 = state[0][c], state[1][c], state[2][c], state[3][c]
        state[0][c] = MUL[14][a0] ^ MUL[11][a1] ^ MUL[13][a2] ^ MUL[9][a3]
        state[1][c] = MUL[9][a0] ^ MUL[14][a1] ^ MUL[11][a2] ^ MUL[13][a3]
        state[2][c] = MUL[13][a0] ^ MUL[9][a1] ^ MUL[14][a2] ^ MUL[11][a3]
        state[3][c] = MUL[11][a0] ^ MUL[13][a1] ^ MUL[9][a2] ^ MUL[14][a3]


def _to_state(block):
    return [[block[r + 4 * c] for c in range(4)] for r in range(4)]


def _from_state(state):
    return bytes(state[r][c] for c in range(4) for r in range(4))


class AESCore:
    """One expanded key; encrypt_block / decrypt_block on 16 bytes."""

    block_size = BLOCK_SIZE

    def __init__(self, key):
        if len(key) not in (16, 24, 32):
            raise ValueError("Incorrect AES key length (%d bytes)" % len(key))
        self.key = bytes(key)
        self._words, self._rounds = _expand_key(self.key)

    def encrypt_block(self, block):
        state = _to_state(block)
        _add_round_key(state, self._words, 0)
        for round_number in range(1, self._rounds):
            for r in range(4):
                for c in range(4):
                    state[r][c] = SBOX[state[r][c]]
            for r in range(1, 4):                            # ShiftRows
                state[r] = state[r][r:] + state[r][:r]
            _mix_columns(state)
            _add_round_key(state, self._words, round_number)
        for r in range(4):
            for c in range(4):
                state[r][c] = SBOX[state[r][c]]
        for r in range(1, 4):
            state[r] = state[r][r:] + state[r][:r]
        _add_round_key(state, self._words, self._rounds)
        return _from_state(state)

    def decrypt_block(self, block):
        state = _to_state(block)
        _add_round_key(state, self._words, self._rounds)
        for round_number in range(self._rounds - 1, 0, -1):
            for r in range(1, 4):                            # InvShiftRows
                state[r] = state[r][-r:] + state[r][:-r]
            for r in range(4):
                for c in range(4):
                    state[r][c] = INV_SBOX[state[r][c]]
            _add_round_key(state, self._words, round_number)
            _inv_mix_columns(state)
        for r in range(1, 4):
            state[r] = state[r][-r:] + state[r][:-r]
        for r in range(4):
            for c in range(4):
                state[r][c] = INV_SBOX[state[r][c]]
        _add_round_key(state, self._words, 0)
        return _from_state(state)
