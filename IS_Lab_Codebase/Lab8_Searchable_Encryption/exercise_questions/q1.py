# LAB 8 - EXERCISE 1 : SYMMETRIC SEARCHABLE ENCRYPTION (SSE)
#   1a create a corpus of at least ten documents
#   1b AES encryption and decryption functions
#   1c build an inverted index (word -> document ids) and encrypt it
#   1d search: encrypt the query, match it in the encrypted index,
#      decrypt the returned document ids and show the documents
#
# THE IMPORTANT DETAIL THE MANUAL'S LISTING GETS WRONG
#   AES-CBC uses a random IV, so encrypting the same word twice gives two
#   different ciphertexts. If you use the encrypted word as the index KEY
#   (as the manual's sample does) no query will ever match.
#   The fix is a DETERMINISTIC keyed token for the key, and randomised
#   encryption only for the values:
#       index key   = HMAC-SHA256(secret_key, word)      deterministic
#       index value = AES-CBC(secret_key, document_id)   randomised
#   That is exactly how real SSE schemes are built.

import hashlib
import hmac
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


# ---------- 1b : encryption and decryption ----------

def encrypt_data(key, data):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv, cipher.encrypt(pad(data.encode(), AES.block_size))


def decrypt_data(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()


def make_token(key, word):
    # the trapdoor: deterministic, keyed, and it reveals nothing about the word
    return hmac.new(key, word.lower().encode(), hashlib.sha256).hexdigest()


# ---------- 1c : the inverted index, encrypted ----------

def create_index(documents, key):
    index = {}
    for doc_id, text in documents.items():
        for word in set(text.lower().split()):          # set() avoids duplicates
            token = make_token(key, word)
            iv, encrypted_id = encrypt_data(key, doc_id)
            index.setdefault(token, []).append((iv, encrypted_id))
    return index


def encrypt_documents(documents, key):
    # the documents themselves are stored encrypted too
    return {doc_id: encrypt_data(key, text) for doc_id, text in documents.items()}


# ---------- 1d : search ----------

def search(index, store, query, key):
    token = make_token(key, query)
    if token not in index:
        return []
    results = []
    for iv, encrypted_id in index[token]:
        doc_id = decrypt_data(key, iv, encrypted_id)
        doc_iv, doc_ct = store[doc_id]
        results.append((doc_id, decrypt_data(key, doc_iv, doc_ct)))
    return sorted(set(results))


def search_multi(index, store, query, key):
    # several words: intersect the posting lists (an AND query)
    words = query.lower().split()
    sets = []
    for word in words:
        hits = {doc_id for doc_id, _ in search(index, store, word, key)}
        sets.append(hits)
    if not sets:
        return []
    common = set.intersection(*sets)
    return sorted((doc_id, decrypt_data(key, *store[doc_id])) for doc_id in common)


# ---------- 1a : the corpus ----------

documents = {
    "doc1": "this is a document with some words",
    "doc2": "another document with different words",
    "doc3": "python is a programming language",
    "doc4": "encryption protects sensitive data",
    "doc5": "secure data requires encryption",
    "doc6": "searchable encryption searches documents",
    "doc7": "python supports cryptographic algorithms",
    "doc8": "aes encrypts data using a secret key",
    "doc9": "hashing creates a fixed size digest",
    "doc10": "secure search finds matching words"
}

key = get_random_bytes(16)                   # the single shared secret key
encrypted_index = create_index(documents, key)
encrypted_store = encrypt_documents(documents, key)

print("=" * 70)
print(" SSE : %d documents, %d distinct search tokens"
      % (len(documents), len(encrypted_index)))
print("=" * 70)
print()
print("--- what the server actually stores (nothing readable) ---")
for token in list(encrypted_index)[:3]:
    print(" token", token[:24] + "...", "->",
          len(encrypted_index[token]), "encrypted id(s)")
print(" ...")
print(" doc1 stored as:", encrypted_store["doc1"][1].hex()[:48] + "...")
print()

for query in ["data", "python", "encryption", "words", "quantum"]:
    print("--- search:", query, "---")
    hits = search(encrypted_index, encrypted_store, query, key)
    if hits:
        for doc_id, text in hits:
            print("  %-6s %s" % (doc_id, text))
    else:
        print("  no matching documents found")
    print()

print("--- AND search: 'secure data' ---")
for doc_id, text in search_multi(encrypted_index, encrypted_store, "secure data", key):
    print("  %-6s %s" % (doc_id, text))
print()

print("--- the point ---")
print("The server matched a %d-character token and returned ciphertext." % 64)
print("It never saw the word 'data', and it never saw a document.")
print("What it CAN see: how many documents matched, and which tokens are")
print("asked about most often. That is the known leakage of SSE.")
print()

query = input("Enter a word to search (Enter to quit): ").strip()
while query:
    hits = search(encrypted_index, encrypted_store, query, key)
    if hits:
        for doc_id, text in hits:
            print(" ", doc_id, ":", text)
    else:
        print("  no matching documents found")
    query = input("Enter a word to search (Enter to quit): ").strip()
