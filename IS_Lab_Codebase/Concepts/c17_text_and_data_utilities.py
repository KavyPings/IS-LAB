"""
=============================================================================
 CONCEPT 17 : TEXT AND DATA UTILITIES
=============================================================================
The small operations that show up as PART of a bigger question:
"remove the spaces and numbers before encrypting", "convert to uppercase",
"strip punctuation", "split into blocks of eight", "print it in hex".

Every one of these is a one-liner, but they are easy to forget under exam
pressure, so they are written out as named functions you can paste.

Nothing here needs an import beyond the standard library.
=============================================================================
"""

import base64
import json
import os
import re
import string
from datetime import datetime, timedelta


# ---------------------------------------------------------------------------
# CASE
# ---------------------------------------------------------------------------

def to_upper(text):
    """'Hello World' -> 'HELLO WORLD'"""
    return str(text).upper()


def to_lower(text):
    """'Hello World' -> 'hello world'"""
    return str(text).lower()


def to_title(text):
    """'hello world' -> 'Hello World'"""
    return str(text).title()


def swap_case(text):
    """'Hello' -> 'hELLO'"""
    return str(text).swapcase()


def capitalise_first(text):
    """'hello world' -> 'Hello world'"""
    return str(text).capitalize()


# ---------------------------------------------------------------------------
# REMOVING THINGS
# ---------------------------------------------------------------------------

def remove_numbers(text):
    """'ab12cd34' -> 'abcd'   (drop every digit)"""
    return "".join(c for c in str(text) if not c.isdigit())


def keep_numbers(text):
    """'ab12cd34' -> '1234'   (keep only the digits)"""
    return "".join(c for c in str(text) if c.isdigit())


def remove_letters(text):
    """'ab12cd34' -> '1234'"""
    return "".join(c for c in str(text) if not c.isalpha())


def keep_letters(text):
    """'He said: hi! 42' -> 'Hesaidhi'"""
    return "".join(c for c in str(text) if c.isalpha())


def remove_spaces(text):
    """'the house is sold' -> 'thehouseissold'"""
    return str(text).replace(" ", "")


def remove_whitespace(text):
    """Also removes tabs and newlines."""
    return "".join(str(text).split())


def remove_punctuation(text):
    """'Hi, there! (ok)' -> 'Hi there ok'  -> drops punctuation only"""
    return "".join(c for c in str(text) if c not in string.punctuation)


def keep_alphanumeric(text):
    """'a-b_c 1!' -> 'abc1'"""
    return "".join(c for c in str(text) if c.isalnum())


def remove_characters(text, unwanted):
    """remove_characters('hello world', 'lo') -> 'he wrd'"""
    return "".join(c for c in str(text) if c not in unwanted)


def keep_characters(text, wanted):
    """keep_characters('hello world', 'lo') -> 'llool'"""
    return "".join(c for c in str(text) if c in wanted)


def remove_vowels(text):
    return "".join(c for c in str(text) if c not in "aeiouAEIOU")


def remove_duplicates(text):
    """'programming' -> 'progamin'  (keeps the first occurrence, in order)"""
    seen, out = set(), []
    for c in str(text):
        if c not in seen:
            seen.add(c)
            out.append(c)
    return "".join(out)


def remove_non_ascii(text):
    return "".join(c for c in str(text) if ord(c) < 128)


def squeeze_spaces(text):
    """'a    b   c' -> 'a b c'"""
    return re.sub(r"\s+", " ", str(text)).strip()


# ---------------------------------------------------------------------------
# THE ONE EVERY CLASSICAL CIPHER NEEDS
# ---------------------------------------------------------------------------

def clean_for_cipher(text, keep_spaces=False):
    """Uppercase letters only - the standard input for Lab 1 ciphers.

    'The house is being sold tonight!' -> 'THEHOUSEISBEINGSOLDTONIGHT'
    """
    text = str(text).upper()
    allowed = string.ascii_uppercase + (" " if keep_spaces else "")
    return "".join(c for c in text if c in allowed)


def clean_for_playfair(text):
    """Playfair merges I and J and works on a 5x5 grid."""
    return clean_for_cipher(text).replace("J", "I")


def pad_to_multiple(text, size, filler="X"):
    """Hill and transposition need a length that divides evenly."""
    text = str(text)
    if len(text) % size:
        text += filler * (size - len(text) % size)
    return text


def split_blocks(data, size):
    """'ABCDEFGH', 3 -> ['ABC', 'DEF', 'GH']   works on str and bytes"""
    return [data[i:i + size] for i in range(0, len(data), size)]


def split_pairs(text, filler="X"):
    """Playfair digraphs: 'BALLOON' -> ['BA', 'LX', 'LO', 'ON']"""
    text = clean_for_playfair(text)
    pairs = []
    i = 0
    while i < len(text):
        a = text[i]
        b = text[i + 1] if i + 1 < len(text) else filler
        if a == b:
            b = filler
            i += 1
        else:
            i += 2
        pairs.append(a + b)
    return pairs


# ---------------------------------------------------------------------------
# LETTERS AND NUMBERS
# ---------------------------------------------------------------------------

def letter_to_number(ch):
    """'A' -> 0 ... 'Z' -> 25"""
    return ord(str(ch).upper()) - 65


def number_to_letter(n):
    """0 -> 'A' ... 25 -> 'Z', wrapping round"""
    return chr(int(n) % 26 + 65)


def text_to_numbers(text):
    """'ABC' -> [0, 1, 2]"""
    return [letter_to_number(c) for c in clean_for_cipher(text)]


def numbers_to_text(numbers):
    """[0, 1, 2] -> 'ABC'"""
    return "".join(number_to_letter(n) for n in numbers)


def shift_letter(ch, amount):
    """Caesar on one character, leaving anything else alone."""
    if not str(ch).isalpha():
        return ch
    base = 65 if ch.isupper() else 97
    return chr((ord(ch) - base + amount) % 26 + base)


def letter_frequency(text):
    """{'E': 12, 'T': 9, ...} sorted most common first - for frequency attacks."""
    counts = {}
    for c in clean_for_cipher(text):
        counts[c] = counts.get(c, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: -kv[1]))


# ---------------------------------------------------------------------------
# BYTES, HEX, BINARY, BASE64
# ---------------------------------------------------------------------------

def to_bytes(value, encoding="utf-8"):
    """str / int / list of ints / bytes -> bytes"""
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, int):
        return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if isinstance(value, (list, tuple)):
        return bytes(value)
    return str(value).encode(encoding)


def to_text(data):
    """bytes -> str, never raising on tampered data."""
    if isinstance(data, (bytes, bytearray)):
        return bytes(data).decode(errors="replace")
    return str(data)


def to_hex(value, group=0, upper=True):
    """to_hex(b'\\xa1\\xb2') -> 'A1B2' ; group=2 -> 'A1 B2'"""
    raw = to_bytes(value).hex()
    if upper:
        raw = raw.upper()
    if group:
        return " ".join(raw[i:i + group * 2] for i in range(0, len(raw), group * 2))
    return raw


def from_hex(text):
    """'a1 b2' or '0xa1 0xb2' or 'a1b2' -> b'\\xa1\\xb2'"""
    text = str(text).lower().replace("0x", "").replace(",", " ")
    text = "".join(text.split())
    return bytes.fromhex(text)


def manual_hex_format(data):
    """The format the lab manual prints signatures in: '0xc8 0x93 ...'"""
    return " ".join("0x%02x" % b for b in to_bytes(data))


def to_binary(value, width=8):
    """b'AB' -> '01000001 01000010'"""
    return " ".join(format(b, "0%db" % width) for b in to_bytes(value))


def from_binary(text):
    bits = "".join(str(text).split())
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))


def to_base64(value):
    return base64.b64encode(to_bytes(value)).decode()


def from_base64(text):
    return base64.b64decode(text)


def to_int(value):
    """bytes or str -> one big integer, for RSA / ElGamal / Rabin."""
    return int.from_bytes(to_bytes(value), "big")


def from_int(number, size=None):
    size = size or max(1, (int(number).bit_length() + 7) // 8)
    return int(number).to_bytes(size, "big")


def xor_bytes(a, b):
    """Equal lengths: one-time pad. Unequal: b is repeated as a key."""
    a, b = to_bytes(a), to_bytes(b)
    if len(a) == len(b):
        return bytes(x ^ y for x, y in zip(a, b))
    return bytes(x ^ b[i % len(b)] for i, x in enumerate(a))


def hamming_distance(a, b):
    """How many BITS differ - the avalanche-effect measurement."""
    a, b = to_bytes(a), to_bytes(b)
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def flip_one_bit(data, position=0):
    """Tamper with a record so an integrity check can be demonstrated."""
    raw = bytearray(to_bytes(data))
    raw[position % len(raw)] ^= 0x01
    return bytes(raw)


# ---------------------------------------------------------------------------
# NUMBERS, VALIDATION, PRINTING
# ---------------------------------------------------------------------------

def is_number(text):
    """Safe input check: is_number('12') -> True, is_number('1a') -> False"""
    try:
        float(text)
        return True
    except (TypeError, ValueError):
        return False


def ask_int(prompt, default=0):
    """An input() that does not crash the menu on bad typing."""
    answer = input(prompt).strip()
    return int(answer) if answer.lstrip("-").isdigit() else default


def digits_of(text):
    """'B001' -> 1 ; useful when a record id must become a number."""
    found = keep_numbers(text)
    return int(found) if found else 0


def short(value, n=44):
    """Keep long ciphertexts from filling the screen."""
    text = str(value)
    return text if len(text) <= n else text[:n] + "..."


def table(rows, headers=None):
    """Print a list of tuples as aligned columns."""
    rows = [tuple(str(c) for c in row) for row in rows]
    if headers:
        rows = [tuple(headers)] + rows
    if not rows:
        return
    widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]))]
    for index, row in enumerate(rows):
        print("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)))
        if headers and index == 0:
            print("  ".join("-" * w for w in widths))


def timestamp(fmt="%Y-%m-%d %H:%M:%S"):
    return datetime.now().strftime(fmt)


def parse_timestamp(text, fmt="%Y-%m-%d %H:%M:%S"):
    return datetime.strptime(str(text), fmt)


def within_window(stamp, opens, closes):
    """Deadline check. The strings sort correctly because of the format."""
    return str(opens) <= str(stamp) <= str(closes)


def minutes_between(start, end):
    """Every 'YYYY-MM-DD HH:MM' from start to end inclusive."""
    t0 = parse_timestamp(str(start)[:16], "%Y-%m-%d %H:%M")
    t1 = parse_timestamp(str(end)[:16], "%Y-%m-%d %H:%M")
    out = []
    while t0 <= t1:
        out.append(t0.strftime("%Y-%m-%d %H:%M"))
        t0 += timedelta(minutes=1)
    return out


def save_json(obj, path):
    json.dump(obj, open(path, "w"), indent=2, default=str)


def load_json(path, default=None):
    if os.path.exists(path):
        return json.load(open(path))
    return {} if default is None else default


def read_text(path, encoding="utf-8"):
    """Closes the handle, which matters on Windows before deleting the file."""
    with open(path, encoding=encoding) as handle:
        return handle.read()


def write_text(path, text, encoding="utf-8"):
    with open(path, "w", encoding=encoding) as handle:
        handle.write(text)


def remove_files(*paths):
    """Best effort cleanup; never raises, so a reset menu item cannot crash."""
    for path in paths:
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            pass


if __name__ == "__main__":
    sample = "The House, is Being Sold 24 toNight! (urgent)"
    print("original            :", sample)
    print("to_upper            :", to_upper(sample))
    print("to_lower            :", to_lower(sample))
    print("swap_case           :", swap_case(sample))
    print("remove_numbers      :", remove_numbers(sample))
    print("keep_numbers        :", keep_numbers(sample))
    print("remove_punctuation  :", remove_punctuation(sample))
    print("remove_spaces       :", remove_spaces(sample))
    print("squeeze_spaces      :", squeeze_spaces("a    b   c"))
    print("remove_characters   :", remove_characters(sample, "aeiou"))
    print("remove_duplicates   :", remove_duplicates("programming"))
    print("clean_for_cipher    :", clean_for_cipher(sample))
    print("clean_for_playfair  :", clean_for_playfair("JUMP JIVE"))
    print("pad_to_multiple     :", pad_to_multiple("ABCDE", 3))
    print("split_blocks        :", split_blocks("ABCDEFGH", 3))
    print("split_pairs         :", split_pairs("BALLOON"))
    print()
    print("text_to_numbers     :", text_to_numbers("ABC"))
    print("numbers_to_text     :", numbers_to_text([0, 1, 2]))
    print("shift_letter        :", "".join(shift_letter(c, 3) for c in "Hello, World!"))
    print("letter_frequency    :", list(letter_frequency(sample).items())[:5])
    print()
    print("to_hex              :", to_hex(b"Hi there"))
    print("to_hex grouped      :", to_hex(b"Hi there", group=2))
    print("from_hex            :", from_hex("48 69"))
    print("manual_hex_format   :", manual_hex_format(b"\xc8\x93"))
    print("to_binary           :", to_binary(b"AB"))
    print("from_binary         :", from_binary("01000001 01000010"))
    print("to_base64           :", to_base64(b"Hi there"))
    print("to_int / from_int   :", to_int(b"Hi"), from_int(to_int(b"Hi")))
    print("xor_bytes           :", to_hex(xor_bytes(b"ABCD", b"    ")))
    print("hamming_distance    :", hamming_distance(b"ABCD", b"ABCE"), "bits")
    print("flip_one_bit        :", to_hex(flip_one_bit(b"ABCD", 0)))
    print()
    print("digits_of('B001')   :", digits_of("B001"))
    print("is_number('12.5')   :", is_number("12.5"), " is_number('1a'):", is_number("1a"))
    print("short               :", short("x" * 60))
    print("timestamp           :", timestamp())
    print("within_window       :", within_window(timestamp(),
                                                 "2000-01-01 00:00:00",
                                                 "2099-12-31 23:59:59"))
    print("minutes_between     :", minutes_between("2025-11-03 10:00", "2025-11-03 10:03"))
    print()
    table([("B001", "101", "accepted"), ("B002", "102", "rejected")],
          headers=("ID", "TAG", "STATUS"))
