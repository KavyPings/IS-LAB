# LAB 8 - ADDITIONAL QUESTION 3
# "Analyse the security and efficiency trade-offs" - the third objective of
# the lab. Everything an exam question can ask on top of a plain keyword
# search, in one file:
#
#   1 AND / OR / NOT queries over the encrypted index
#   2 PREFIX search, by indexing every prefix as its own token
#   3 RANGE search on a number (dates, amounts, constituencies) by bucketing
#   4 a DYNAMIC index: adding and deleting documents after it was built
#   5 the leakage: a counting attack that recovers keywords from the index
#     alone, and the padding that stops it
#
# Everything uses the same two primitives as exercise 1:
#     token = HMAC-SHA256(key, label)       deterministic
#     value = AES-CBC(key, document_id)     randomised

import hashlib
import hmac
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

BUCKET = 100                   # range search granularity


def encrypt_data(key, data):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv, cipher.encrypt(pad(data.encode(), 16))


def decrypt_data(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), 16).decode()


def token(key, label):
    return hmac.new(key, label.lower().encode(), hashlib.sha256).hexdigest()


class EncryptedIndex:
    # a small class only because the index needs to be added to and deleted
    # from after it is built; everything else in this lab is plain functions

    def __init__(self, key):
        self.key = key
        self.index = {}                 # token -> [(iv, encrypted id)]
        self.deleted = set()            # tokens of removed ids (revocation list)

    def add_label(self, label, doc_id):
        iv, encrypted = encrypt_data(self.key, doc_id)
        self.index.setdefault(token(self.key, label), []).append((iv, encrypted))

    def add_document(self, doc_id, text, number=None):
        words = set(text.lower().split())
        for word in words:
            self.add_label(word, doc_id)
            for size in range(3, len(word)):            # prefix tokens
                self.add_label("pre:" + word[:size], doc_id)
        if number is not None:
            self.add_label("num:%d" % (number // BUCKET), doc_id)

    def delete_document(self, doc_id):
        # the server must not be told which postings to remove, so instead the
        # id is put on an encrypted revocation list and filtered out on search
        self.deleted.add(token(self.key, "del:" + doc_id))

    def lookup(self, label):
        hits = []
        for iv, encrypted in self.index.get(token(self.key, label), []):
            doc_id = decrypt_data(self.key, iv, encrypted)
            if token(self.key, "del:" + doc_id) in self.deleted:
                continue
            hits.append(doc_id)
        return set(hits)

    def search_and(self, *words):
        sets = [self.lookup(w) for w in words]
        return sorted(set.intersection(*sets)) if sets else []

    def search_or(self, *words):
        found = set()
        for word in words:
            found |= self.lookup(word)
        return sorted(found)

    def search_not(self, word, universe):
        return sorted(set(universe) - self.lookup(word))

    def search_prefix(self, prefix):
        if len(prefix) < 3:
            return sorted(self.lookup(prefix))
        return sorted(self.lookup("pre:" + prefix))

    def search_range(self, low, high):
        found = set()
        for bucket in range(low // BUCKET, high // BUCKET + 1):
            found |= self.lookup("num:%d" % bucket)
        return sorted(found)


documents = {
    "doc1": ("encryption protects sensitive financial data", 150),
    "doc2": ("secure financial reports require encryption", 220),
    "doc3": ("python programming for security engineers", 310),
    "doc4": ("searchable encryption searches encrypted documents", 420),
    "doc5": ("hashing creates a fixed size digest", 480),
    "doc6": ("secure financial audit of encrypted records", 640),
    "doc7": ("network security monitoring and intrusion detection", 710),
    "doc8": ("sensitive medical records need encryption", 830),
    "doc9": ("public key cryptography and digital signatures", 905),
    "doc10": ("secure search over encrypted financial records", 980)
}

key = get_random_bytes(16)
store = EncryptedIndex(key)
for doc_id, (text, number) in documents.items():
    store.add_document(doc_id, text, number)

print("=" * 74)
print(" SSE with AND / OR / NOT, prefix, range, updates and leakage analysis")
print("=" * 74)
print("documents: %d   tokens in the index: %d" % (len(documents), len(store.index)))
print()

print("--- 1 boolean queries ---")
print(" AND  secure + financial      ->", store.search_and("secure", "financial"))
print(" OR   medical | network       ->", store.search_or("medical", "network"))
print(" NOT  not encryption          ->", store.search_not("encryption", documents))
print()

print("--- 2 prefix search ---")
print(" encr*   ->", store.search_prefix("encr"))
print(" sec*    ->", store.search_prefix("sec"))
print(" finan*  ->", store.search_prefix("finan"))
print(" cost: every word of length L adds L-3 extra tokens, so the index")
print("       grows roughly with the total number of characters, not words")
print()

print("--- 3 range search on the numeric field (bucket size %d) ---" % BUCKET)
print(" 100 .. 400   ->", store.search_range(100, 400))
print(" 600 .. 1000  ->", store.search_range(600, 1000))
print(" leakage: the server learns which BUCKET was asked for, not the value.")
print(" smaller buckets mean finer queries and more leakage; bigger buckets")
print(" mean the client has to filter more false hits itself.")
print()

print("--- 4 a dynamic index ---")
store.add_document("doc11", "new encrypted financial statement", 505)
print(" after adding doc11, AND secure+financial   ->",
      store.search_and("secure", "financial"))
print(" AND encrypted+financial                    ->",
      store.search_and("encrypted", "financial"))
store.delete_document("doc2")
print(" after deleting doc2, AND secure+financial  ->",
      store.search_and("secure", "financial"))
print(" the postings for doc2 are still on the server; they are filtered by an")
print(" encrypted revocation list. Real dynamic SSE calls this the price of")
print(" forward and backward privacy.")
print()

print("--- 5 the leakage, and a counting attack ---")
sizes = sorted(((len(v), t) for t, v in store.index.items() if not t.startswith("x")),
               reverse=True)[:6]
print(" the server cannot read a token, but it CAN count its postings:")
for count, tok in sizes:
    print("   token %s...  %d documents" % (tok[:16], count))
print()
print(" if the attacker knows the document collection is a corpus of financial")
print(" reports, it knows roughly how often each English word should appear.")
print(" matching the observed counts against that frequency table recovers the")
print(" most common keywords. This is the 'count attack' on SSE.")
print()
print(" the standard defence is PADDING: make every posting list the same")
print(" length with dummy entries, so counts carry no information.")
real = max(len(v) for v in store.index.values())
padded = {t: v + [encrypt_data(key, "dummy") for _ in range(real - len(v))]
          for t, v in store.index.items()}
print("   before padding: posting lists of sizes",
      sorted({len(v) for v in store.index.values()}))
print("   after padding : posting lists of sizes",
      sorted({len(v) for v in padded.values()}))
print("   storage cost  : %d -> %d postings (%.1fx)"
      % (sum(len(v) for v in store.index.values()),
         sum(len(v) for v in padded.values()),
         sum(len(v) for v in padded.values()) / sum(len(v) for v in store.index.values())))
print()

print("--- the trade-off table to put in the write-up ---")
print(" %-22s %-14s %-18s" % ("feature", "cost", "extra leakage"))
print(" " + "-" * 60)
print(" %-22s %-14s %-18s" % ("exact keyword", "1 HMAC", "result count"))
print(" %-22s %-14s %-18s" % ("AND / OR", "n lookups", "each term's count"))
print(" %-22s %-14s %-18s" % ("prefix", "L tokens/word", "prefix frequency"))
print(" %-22s %-14s %-18s" % ("range", "k buckets", "which bucket"))
print(" %-22s %-14s %-18s" % ("updates", "revocation list", "update pattern"))
print(" %-22s %-14s %-18s" % ("padding", "x%.1f storage" % (
    sum(len(v) for v in padded.values()) / sum(len(v) for v in store.index.values())),
    "none from counts"))
