# LAB 8 - EXERCISE 2 : PUBLIC-KEY SEARCHABLE ENCRYPTION (PKSE)
#   2a a corpus of at least ten documents
#   2b encryption and decryption with the PAILLIER cryptosystem
#   2c an inverted index whose document ids are Paillier encrypted
#   2d search: hash the query, look it up, Paillier-decrypt the ids
#
# WHY PAILLIER HERE
#   The manual asks for Paillier in exercise 2. Paillier encrypts NUMBERS,
#   so the document id "doc7" is stored as the number 7. The owner of the
#   private key is the only one who can turn the posting list back into ids.
#
# WHY THE INDEX KEY IS A PLAIN HASH, NOT A PUBLIC-KEY CIPHERTEXT
#   Every secure public-key encryption is randomised, so encrypting the same
#   word twice gives different ciphertexts and the lookup would never match.
#   (The manual's PKSE listing has exactly this bug: it encrypts the query
#   hash with PKCS1_OAEP and compares it to a stored OAEP ciphertext.)
#   Real PKSE (Boneh et al., "Public Key Encryption with Keyword Search")
#   solves it with pairings. At lab level the honest, working version is:
#       index key   = SHA-256(word)              deterministic, public
#       index value = Paillier(document number)  randomised, private key needed
#   and the write-up should say that the deterministic key is what leaks.

from Crypto.Util.number import getPrime, GCD
import hashlib
import random

BITS = 512


# ---------- 2b : Paillier ----------

def generate_keypair(bits=BITS):
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    while p == q:
        q = getPrime(bits // 2)
    n = p * q
    lam = (p - 1) * (q - 1)
    return {"n": n, "nn": n * n}, {"lam": lam, "n": n, "nn": n * n}


def encrypt(public_key, m):
    n, nn = public_key["n"], public_key["nn"]
    r = random.randrange(1, n)
    while GCD(r, n) != 1:
        r = random.randrange(1, n)
    return ((1 + m * n) * pow(r, n, nn)) % nn


def decrypt(private_key, c):
    n, nn, lam = private_key["n"], private_key["nn"], private_key["lam"]
    u = (pow(c, lam, nn) - 1) // n
    return (u * pow(lam, -1, n)) % n


def make_token(word):
    # deterministic and public: anybody can build the index, which is the
    # whole selling point of PKSE
    return hashlib.sha256(word.lower().encode()).hexdigest()


# ---------- 2c : the encrypted index ----------

def create_index(documents, public_key):
    index = {}
    for doc_id, text in documents.items():
        number = int(doc_id[3:])                        # "doc7" -> 7
        for word in set(text.lower().split()):
            index.setdefault(make_token(word), []).append(encrypt(public_key, number))
    return index


# ---------- 2d : search ----------

def search(index, query, private_key, documents):
    token = make_token(query)
    if token not in index:
        return []
    results = []
    for encrypted_id in index[token]:
        number = decrypt(private_key, encrypted_id)     # private key needed
        doc_id = "doc" + str(number)
        results.append((doc_id, documents[doc_id]))
    return sorted(set(results))


def count_matches(index, query, public_key):
    # the SERVER can count hits without any key at all
    return len(index.get(make_token(query), []))


# ---------- 2a : the corpus ----------

documents = {
    "doc1": "python programming language",
    "doc2": "secure data encryption",
    "doc3": "python supports encryption",
    "doc4": "computer networks and security",
    "doc5": "data structures and algorithms",
    "doc6": "searchable encryption system",
    "doc7": "python programming basics",
    "doc8": "secure communication protocols",
    "doc9": "cryptography protects data",
    "doc10": "encryption and security"
}

public_key, private_key = generate_keypair()
index = create_index(documents, public_key)

print("=" * 70)
print(" PKSE : %d documents, %d search tokens, Paillier n = %s"
      % (len(documents), len(index), hex(public_key["n"])[:22] + "..."))
print("=" * 70)
print()
print("--- anybody with the PUBLIC key can add to the index ---")
token = make_token("python")
print(" token for 'python':", token[:32] + "...")
print(" posting list      :", [hex(c)[:14] + "..." for c in index[token]])
print(" the server can count matches without a key:",
      count_matches(index, "python", public_key))
print(" but it cannot tell WHICH documents they are")
print()

for query in ["python", "encryption", "data", "security", "blockchain"]:
    print("--- search:", query, "---")
    hits = search(index, query, private_key, documents)
    if hits:
        for doc_id, text in hits:
            print("  %-6s %s" % (doc_id, text))
    else:
        print("  no matching documents")
    print()

print("--- SSE vs PKSE, the comparison the manual asks for ---")
print(" SSE  : one shared secret key. Fast (HMAC + AES). Everyone who can")
print("        search can also write and decrypt. Key distribution is the pain.")
print(" PKSE : public key to write, private key to read. Many writers, one")
print("        reader. Flexible access control, but every index entry costs a")
print("        public-key operation, so it is far slower.")
print()
print("--- the leakage to admit in the write-up ---")
print(" deterministic tokens mean the server sees which words repeat, and can")
print(" match a token against a dictionary of common words. Randomised tokens")
print(" would need pairing-based PEKS, which is outside this syllabus.")
print()

query = input("Enter search word (Enter to quit): ").strip()
while query:
    hits = search(index, query, private_key, documents)
    if hits:
        for doc_id, text in hits:
            print(" ", doc_id, ":", text)
    else:
        print("  no matching documents")
    query = input("Enter search word (Enter to quit): ").strip()
