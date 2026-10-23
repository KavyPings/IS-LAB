"""
=============================================================================
 CONCEPT 15 : SEARCHABLE ENCRYPTION   (Lab 8)
=============================================================================
Letting a server FIND a record it cannot READ.

  index KEY   must be DETERMINISTIC, or no query will ever match
                SSE  : HMAC-SHA256(secret_key, label)
                PKSE : SHA-256(label)            public, anyone can index
  index VALUE must be RANDOMISED, or the ids leak
                SSE  : AES-CBC(secret_key, record_id)
                PKSE : Paillier(record_number)

The manual's sample code encrypts the WORD and uses that as the index key.
AES-CBC and RSA-OAEP are randomised, so that lookup can never match. Use the
split above instead.

Labels, not just words, are what scenario questions search on:
    "const:101"            search by constituency / department / branch
    "time:2025-11-03 10:05" one bucket per minute, a range expands to buckets
    "num:4"                 a number bucket, for "amount between X and Y"
=============================================================================
"""

import hashlib
import hmac
import random
from datetime import datetime, timedelta

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import GCD, getPrime


# ---------------------------------------------------------------------------
# the two primitives
# ---------------------------------------------------------------------------

def se_encrypt(key, data):
    """AES-CBC with a fresh IV. Returns (iv, ciphertext)."""
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv, cipher.encrypt(pad(data.encode(), 16))


def se_decrypt(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), 16).decode(errors="replace")


def sse_token(key, label):
    """Keyed, deterministic trapdoor. Reveals nothing about the label."""
    return hmac.new(key, str(label).lower().encode(), hashlib.sha256).hexdigest()


def pkse_token(label):
    """Unkeyed, deterministic, PUBLIC - anybody can add to the index."""
    return hashlib.sha256(str(label).lower().encode()).hexdigest()


# ---------------------------------------------------------------------------
# SSE : symmetric searchable encryption
# ---------------------------------------------------------------------------

def sse_index_add(index, key, label, record_id):
    iv, encrypted = se_encrypt(key, record_id)
    index.setdefault(sse_token(key, label), []).append([iv.hex(), encrypted.hex()])
    return index


def sse_index_lookup(index, key, label):
    hits = []
    for iv_hex, ct_hex in index.get(sse_token(key, label), []):
        hits.append(se_decrypt(key, bytes.fromhex(iv_hex), bytes.fromhex(ct_hex)))
    return sorted(set(hits))


def sse_build_index(documents, key):
    """documents = {id: text}. Indexes every distinct word of every document."""
    index = {}
    for record_id, text in documents.items():
        for word in set(str(text).lower().split()):
            sse_index_add(index, key, word, record_id)
    return index


# ---------------------------------------------------------------------------
# PKSE : public-key searchable encryption, document ids under Paillier
# ---------------------------------------------------------------------------

def pkse_keygen(bits=512):
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    while p == q:
        q = getPrime(bits // 2)
    n = p * q
    return {"n": n, "nn": n * n}, (p - 1) * (q - 1)


def pkse_encrypt_number(m, pub):
    n, nn = pub["n"], pub["nn"]
    r = random.randrange(1, n)
    while GCD(r, n) != 1:
        r = random.randrange(1, n)
    return ((1 + m * n) * pow(r, n, nn)) % nn


def pkse_decrypt_number(c, pub, secret):
    n, nn = pub["n"], pub["nn"]
    u = (pow(c, secret, nn) - 1) // n
    return (u * pow(secret, -1, n)) % n


def pkse_index_add(index, pub, label, number):
    index.setdefault(pkse_token(label), []).append(str(pkse_encrypt_number(number, pub)))
    return index


def pkse_index_lookup(index, pub, secret, label):
    return sorted({pkse_decrypt_number(int(blob), pub, secret)
                   for blob in index.get(pkse_token(label), [])})


# ---------------------------------------------------------------------------
# labels for the searches scenario questions actually ask for
# ---------------------------------------------------------------------------

def tag_label(field, value):
    """search by constituency / department / branch / category."""
    return "%s:%s" % (field, value)


def minute_label(stamp):
    """one bucket per minute; stamp is 'YYYY-MM-DD HH:MM:SS'."""
    return "time:" + str(stamp)[:16]


def minute_labels_between(start, end):
    """Expand 'from .. to' into the list of minute buckets to look up."""
    t0 = datetime.strptime(str(start)[:16], "%Y-%m-%d %H:%M")
    t1 = datetime.strptime(str(end)[:16], "%Y-%m-%d %H:%M")
    labels = []
    while t0 <= t1:
        labels.append(minute_label(t0.strftime("%Y-%m-%d %H:%M")))
        t0 += timedelta(minutes=1)
    return labels


def number_label(value, bucket=100):
    """search by amount / score range."""
    return "num:%d" % (int(value) // bucket)


def number_labels_between(low, high, bucket=100):
    return ["num:%d" % b for b in range(int(low) // bucket, int(high) // bucket + 1)]


def prefix_labels(word, minimum=3):
    """Index these as well to support 'encr*' style prefix search."""
    word = word.lower()
    return ["pre:" + word[:size] for size in range(minimum, len(word))]


# ---------------------------------------------------------------------------
# boolean queries over any lookup function
# ---------------------------------------------------------------------------

def search_and(lookup, *labels):
    sets = [set(lookup(label)) for label in labels]
    return sorted(set.intersection(*sets)) if sets else []


def search_or(lookup, *labels):
    found = set()
    for label in labels:
        found |= set(lookup(label))
    return sorted(found)


def search_not(lookup, label, universe):
    return sorted(set(universe) - set(lookup(label)))


def pad_posting_lists(index, key, filler="dummy"):
    """Defence against the count attack: every list the same length."""
    longest = max((len(v) for v in index.values()), default=0)
    padded = {}
    for token, entries in index.items():
        extra = []
        for _ in range(longest - len(entries)):
            iv, ct = se_encrypt(key, filler)
            extra.append([iv.hex(), ct.hex()])
        padded[token] = entries + extra
    return padded


if __name__ == "__main__":
    documents = {
        "doc1": "encryption protects sensitive financial data",
        "doc2": "secure financial reports require encryption",
        "doc3": "python programming for security engineers",
        "doc4": "searchable encryption searches encrypted documents",
        "doc5": "secure search over encrypted financial records",
    }

    print("--- SSE ---")
    key = get_random_bytes(16)
    index = sse_build_index(documents, key)
    print("tokens in the index:", len(index))
    print("search 'financial'  ->", sse_index_lookup(index, key, "financial"))
    print("search 'python'     ->", sse_index_lookup(index, key, "python"))
    print("AND secure+financial->", search_and(
        lambda label: sse_index_lookup(index, key, label), "secure", "financial"))
    print("OR python|records   ->", search_or(
        lambda label: sse_index_lookup(index, key, label), "python", "records"))
    print("NOT encryption      ->", search_not(
        lambda label: sse_index_lookup(index, key, label), "encryption", documents))

    print("\n--- labels for scenario searches ---")
    stamp = "2025-11-03 10:05:00"
    sse_index_add(index, key, tag_label("const", 101), "B001")
    sse_index_add(index, key, minute_label(stamp), "B001")
    sse_index_add(index, key, number_label(450), "B001")
    print("by constituency 101 ->", sse_index_lookup(index, key, tag_label("const", 101)))
    hits = []
    for label in minute_labels_between("2025-11-03 10:00", "2025-11-03 10:10"):
        hits += sse_index_lookup(index, key, label)
    print("by time 10:00-10:10 ->", sorted(set(hits)))
    hits = []
    for label in number_labels_between(400, 600):
        hits += sse_index_lookup(index, key, label)
    print("by amount 400-600   ->", sorted(set(hits)))

    print("\n--- PKSE ---")
    pub, secret = pkse_keygen(512)
    pindex = {}
    for record_id, text in documents.items():
        number = int(record_id[3:])
        for word in set(text.lower().split()):
            pkse_index_add(pindex, pub, word, number)
    print("server can count 'financial' matches with no key:",
          len(pindex[pkse_token("financial")]))
    print("private key turns them into ids:",
          ["doc%d" % n for n in pkse_index_lookup(pindex, pub, secret, "financial")])

    print("\n--- padding against the count attack ---")
    print("before:", sorted({len(v) for v in index.values()}))
    print("after :", sorted({len(v) for v in pad_posting_lists(index, key).values()}))
