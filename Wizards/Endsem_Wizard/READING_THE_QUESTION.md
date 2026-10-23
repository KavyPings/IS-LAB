# Reading the question

How to turn an end-sem question into a filled checklist in ten minutes,
using the sample paper as the worked example.

The question looks long. It is not. Every end-sem question in this course is
the **same question** with the nouns changed — an e-voting system, a trade
reporting system, a hospital record system — and the scheme names swapped.
Your whole job in the first ten minutes is to find which scheme name went
into each slot. Nothing else in the question needs a decision.

Sections 1–6 decode the sample paper. **Section 7 is the reference you use
during the exam**: every prompt the wizard asks, what in the question decides
it, what to do when the question is silent, and what each switch costs in
lines. Sections 8–11 cover the traps, the gaps, a second worked question and
a blank worksheet.

---

## 1. What an end-sem question is made of

Five parts, always in this order:

| part | looks like | what you take from it |
| --- | --- | --- |
| **The scenario** | one paragraph, "A national e-voting system has been deployed…" | the nouns: system name, what one record is called |
| **Client side** | a bullet list | which scheme does what, on the way in |
| **Server side** | a bullet list | which scheme does what, on the way out |
| **The task paragraph** | "Write a menu-driven Python program…" | the non-negotiables: menu, storage, show every output |
| **The marking table** | 4–6 rows at the bottom | where the marks are. **Read this first.** |

The marking table is the most valuable thirty words on the paper and the
easiest to skip. Read it before the bullets. It tells you which components
you must not get wrong, and it lets you ignore anything the bullets mention
that no row covers.

---

## 2. The three passes

**Pass 1 — the marking table (1 minute).** Copy the component names onto the
rough sheet as a column. That column is your write-up structure and your
demo order.

**Pass 2 — the nouns (2 minutes).** Four words:

- what is the **system** called → `system name`
- what is **one stored item** called → `record word`
- what do you **search on** → `tag word`
- what gets **added up** → `value word`

Getting these right is free marks. The generated code prints them
everywhere, so the output reads like it was written for this question rather
than pulled off a USB.

**Pass 3 — the schemes (7 minutes).** Go down the client bullets then the
server bullets with the checklist in section 6 beside you, and for each
bullet write **one** checklist line. Most bullets map to exactly one.

Do not write any code during these three passes. Do not open the editor.

---

## 3. The sample paper, pass 1: the marking table

```
| Component     | Writeup | Execution | Remarks |
| Client-Server |         |           |         |
| ED            |         |           |         |
| DSS           |         |           |         |
| Hash          |         |           |         |
| Search        |         |           |         |
```

Five rows, each marked twice (write-up and execution). So:

- **Client-Server is a marked row.** It is not scene-setting. There must be
  a client and a server, visibly. → `sockets = yes`, and use
  `answer_server.py` / `answer_client.py` in two terminals so the examiner
  sees two programs.
- **Search is a marked row** — worth as much as encryption. Easy to run out
  of time before reaching it. Demo it early.
- **Paillier tallying and threshold decryption have no row.** They are in
  the question, so they must work, but if time runs out they are the last
  things you demo, not the first.
- **Access control has no row either** — but the task paragraph names it, so
  it stays on.

Demo order follows this table, top to bottom. Never your build order.

---

## 4. The sample paper, pass 2: the nouns

| the question says | setting | value |
| --- | --- | --- |
| "A national e-voting system" | system name | `SecureVote` |
| "A voter fills out an electronic **ballot**" | record word | `ballot` |
| "locate ballots from specific **constituencies**" | tag word | `ConstituencyID` |
| "the voter's choice (numerical **candidate ID**)" | value word | `CandidateID` |

Note where the tag word came from: the **server** side, from the search
bullet, not the client side. The field you search on is whatever the search
bullet says you look things up by.

---

## 5. The sample paper, pass 3: the bullets, one at a time

### Client side

| the bullet | the setting it sets |
| --- | --- |
| "records their candidate selection and constituency ID" | the two field names (done in pass 2) |
| "generates a **SHA-512** hash of the ballot file to ensure data integrity" | `hash = sha512` |
| "encrypted using **AES-256** in **CBC** mode" | `cipher = AES-256`, `mode = CBC` |
| "The AES key is encrypted with the Election Commission's **RSA-4096** public key" | `key wrap = RSA`, `rsa_bits = 4096` |
| "digitally signs the SHA-512 hash using their **ElGamal** digital signature" | `signature = ELGAMAL` |
| "homomorphically encrypted using the **Paillier** encryption scheme, allowing … tally … without decrypting" | `homomorphic = PAILLIER` |
| "A **timestamp** from a trusted authority … votes are cast before the **deadline**" | `timestamps = yes` |

Seven bullets, seven checklist lines. That is the normal ratio.

Two details worth noticing:

- "signs the SHA-512 **hash**" — the signature covers the digest, not the
  plaintext. That is one sentence of write-up and a likely viva question.
- "RSA-**4096**" is the one number in the question that will cost you time:
  key generation takes 10–60 seconds. Build with 2048, demo, and say in the
  write-up that only the key size differs. Or build 4096 and start the keygen
  while you write.

### Server side

| the bullet | the setting it sets |
| --- | --- |
| "decrypts the AES session key using its RSA private key, but **keeps the homomorphically encrypted vote values in their encrypted form**" | nothing new — this is what `PAILLIER` already does. It is telling you *not* to decrypt the votes |
| "verifies the digital signature using the voter's public key and compares the SHA-512 hash" | nothing new — `ELGAMAL` + `sha512` |
| "The timestamp is checked to confirm … within the valid voting period" | nothing new — `timestamps` |
| "The homomorphic tallying algorithm is then applied to aggregate the encrypted votes" | nothing new — `PAILLIER` |
| "maintains a **searchable encryption index** to locate ballots from specific constituencies or time ranges without revealing vote content" | `search = SSE` |
| "only the final aggregated ciphertext is decrypted using a **threshold decryption** scheme, ensuring that **no single authority** can view votes independently" | `threshold = yes` (2-of-3) |

**Six server bullets; only two new settings.** This is the pattern: the
server side mostly restates the client side from the other end. Do not
re-derive it. Read it to confirm you did not miss a scheme, and to collect
the verbs — *verify, check, tally, search, decrypt* — because those become
the server's role permissions and the menu items.

"Time ranges" in the search bullet is worth a note: the generated SSE index
labels every record with its tag **and** a one-minute time bucket, and a
range query is every bucket between the two ends — so searching by time
range already works, with no extra setting. Show it; it is a sentence of
write-up for free.

### The task paragraph

> "Write a **menu-driven** Python program … supports **role-based access
> control** … use **data structures (e.g., databases, files, arrays)** to
> securely store encrypted, signed, and hashed trade reports. **Show outputs
> for all the functions** specified in the question."

| the phrase | what it sets |
| --- | --- |
| "menu-driven" | not a setting — a **requirement**. Papers halve marks without it. The generated `answer.py` is menu-driven; run the menu, not just `demo` |
| "role-based access control" | `access = RBAC` |
| "use data structures … to securely store" | nothing — the generated code already writes `records.json`, `keys.json`, `index.json`. Open one in Notepad during the demo to prove storage |
| "show outputs for all the functions" | run `demo` once for the transcript, then the menu for the examiner |

And one giveaway: *"…hashed **trade reports**."* The paper was copied from
the trade-reports version of the same question and this noun was missed.
When you see a leftover noun like that, it confirms you are looking at the
standard template — and that the marking table, not the prose, is the
authority.

---

## 6. The filled checklist

That is the whole question. Here it is as the checklist you copy onto the
rough sheet:

```
system name ...... SecureVote
record word ...... ballot
tag word ......... ConstituencyID      (searched on)
value word ....... CandidateID         (totalled)

cipher ........... AES-256
mode ............. CBC
key wrap ......... RSA   (4096 -> build 2048, say so)
hash ............. sha512
signature ........ ELGAMAL
homomorphic ...... PAILLIER
search ........... SSE
access ........... RBAC

key mgmt ......... no        (question never says generate/revoke/renew)
threshold ........ YES 2-of-3
timestamps ....... YES
sockets .......... YES  + split files
hmac ............. no
log chain ........ no
replay ........... no

roles ............ voter   submit, view_own
                   server  verify, search, view_all, tamper_test
                   tally   aggregate, threshold_decrypt
                   auditor view_hashes, audit
```

The roles came from the question's own actors: *voter*, *Election
Commission / server*, *tally authority*, and an *audit* mention in the search
bullet. Name them after the question's words, never `user1`/`user2`.

---

## 7. Answering every prompt

If a preset already matches your checklist, it is one line:

```
python wizard.py --build evoting
```

**Check the preset against your checklist first** — the real paper will
differ somewhere. When it does, run the questions:

```
python wizard.py
```

The prompts come in checklist order and **Enter accepts the shown default**,
so starting from the nearest preset means you only type the lines that
changed. What follows is every prompt, what decides it, and what to do when
the question says nothing.

The rule that covers nine prompts out of ten:

> **If the question names it, use what it names. If the question is silent,
> accept the default and say in the write-up that the question did not
> specify.** Never invent a requirement the paper did not make — a setting
> you turned on is a setting you have to explain in the viva.

---

### 7.1 `scenario`

Pick the **nearest** preset, never `custom`, unless nothing is close. It
costs nothing to override a line afterwards and it saves twenty Enters.

| the question is about | nearest preset |
| --- | --- |
| votes, ballots, tallying, an election | `evoting` |
| trades, transactions, reports, totals per client | `trade` |
| patients, readings, comparing two encrypted values | `medical` |
| accounts, transfers, a bank | `banking` |
| documents, files, keyword search | `documents` |
| hospitals + a key management service | `healthcare` |
| licences, DRM, access that expires | `drm` |
| subsystems exchanging keys inside one company | `enterprise` |
| nothing recognisable | nearest by the **schemes** it names, not the story |

`custom` only if the question is genuinely unlike all nine. `minimal` is for
the ten-minutes-left emergency, not for a real answer.

---

### 7.2 The four nouns

| prompt | what to put | where you find it |
| --- | --- | --- |
| system name | the question's own name, or invent one | the first sentence |
| what is one stored item called | singular, lowercase: `ballot`, `trade`, `record`, `reading` | the client-side bullets |
| the field you search on | the thing the search bullet looks things up **by** | the search bullet, usually server side |
| the numeric field that gets totalled | the one field that gets added, averaged or compared | the homomorphic bullet |

Three mistakes to avoid: a plural (`ballots`), a sentence instead of a word,
and guessing the tag word from the client side. Where the question has no
search bullet, the tag word is whatever you would group records by —
department, branch, constituency.

---

### 7.3 `symmetric cipher`  — AES-128 / AES-192 / AES-256 / DES / 3DES

| the question says | choose | why |
| --- | --- | --- |
| "AES-256", "256-bit AES" | `AES-256` | 32-byte key |
| "AES-128", "AES" with no size | `AES-128` / `AES-256` | if no size is given, AES-256 and say so |
| "DES" | `DES` | 8-byte key, 8-byte blocks — **say in the viva that 56 effective bits is broken today** |
| "3DES", "Triple DES", "DES3" | `3DES` | 24-byte key; pycryptodome rejects a degenerate key where K1 = K2, which the generated code handles |
| nothing | `AES-256` | the modern default |

Block size changes with the cipher (16 bytes for AES, 8 for DES/3DES), and
the generated code pads to the right one by itself. You never have to adjust
anything after changing this.

---

### 7.4 `mode of operation` — CBC / ECB / CFB / OFB / CTR / GCM / EAX

Decide in this order:

1. **Does the question name a mode?** Use it. Done.
2. **Does it say the mode must detect tampering / provide authenticated
   encryption / produce a tag?** → `GCM` (or `EAX`).
3. **Does it say identical plaintexts must look different, or mention an
   IV / nonce?** → any of `CBC`, `CFB`, `OFB`, `CTR` — keep `CBC`.
4. **Silent?** → `CBC`.

| mode | pick it when | watch for |
| --- | --- | --- |
| `CBC` | the default; "with an IV" | needs padding — the `Padding is incorrect` error means a wrong key |
| `ECB` | the question explicitly says ECB, or asks you to *show why ECB is weak* | say out loud that identical blocks encrypt identically; never defend it |
| `CFB` / `OFB` | named; "turns the block cipher into a stream cipher" | no padding needed |
| `CTR` | named; "counter mode", "parallelisable" | no padding; never reuse a nonce |
| `GCM` | "authenticated encryption", "detects modification", "tag" | decryption raises `MAC check failed` on tampering — that is the demo, not a bug |
| `EAX` | named, or GCM is wanted but the paper says EAX | same as GCM in behaviour |

If the marking table has a **Remarks** column and you have spare time, GCM
is the single best unprompted upgrade: it demonstrates integrity *inside*
the cipher, which is a question examiners like asking.

---

### 7.5 `how is the session key sent` — RSA / ECC / ELGAMAL / RABIN / DH / NONE

This is the asymmetric half of ED. Read the bullet that says how the
symmetric key reaches the other side.

| the question says | choose |
| --- | --- |
| "encrypted with the ... RSA public key" | `RSA` |
| "ECC", "elliptic curve", "secp256r1 / P-256", "ECIES" | `ECC` |
| "ElGamal", "public key (p, g, h)" | `ELGAMAL` |
| "Rabin cryptosystem", "Blum primes", "quadratic residue" | `RABIN` |
| "Diffie-Hellman", "the two sides derive a shared secret" | `DH` |
| the key is pre-shared / the question never sends a key | `NONE` |
| nothing | `RSA` |

Three things worth knowing before the viva:

- **`DH` is not key wrapping.** Nothing is encrypted; both sides compute the
  same secret from their own private value. If the question says *"exchange"*
  it is probably DH; if it says *"encrypt the key with"* it is RSA/ECC/ElGamal.
- **`RABIN` decryption produces four roots.** The generated code adds a
  marker so the right one is identifiable — that is a standard exam question.
- **`ECC` here means ECIES**: an ephemeral key, a point multiplication, a KDF,
  then AES-GCM. ECC cannot encrypt a key directly.
- `ELGAMAL` and `RSA` are also the two that can be made *multiplicatively
  homomorphic* (see 7.9), so a question that uses one for both is giving you
  a hint.

---

### 7.6 `RSA key size` (only asked when wrap = RSA)

| the question says | type | but |
| --- | --- | --- |
| nothing | `2048` | the default |
| "RSA-2048" | `2048` | |
| "RSA-1024" | `1024` | add one line saying 1024 is below current guidance |
| "RSA-3072 / RSA-4096" | `2048` **first** | keygen at 4096 takes 10–60 s and you may run it twice |

If the paper says 4096: build at 2048, demo everything, then rebuild at 4096
while you are writing the answer up. Write *"RSA-4096 as specified; the
screenshots were taken at 2048 for time, only the modulus size differs."*
That sentence has never cost a mark. A demo that stalls on keygen has.

---

### 7.7 `hash algorithm`

| the question says | choose |
| --- | --- |
| "SHA-512 / 384 / 256 / 224" | the one named |
| "SHA-3" | `sha3_256` |
| "MD5" or "SHA-1" | the one named — and say in the viva that it is broken (collisions) and is being used only because the question specifies it |
| "write your own hash function", "multiply by 33", "5381", "a custom hash" | `custom` |
| nothing | `sha512` |

The Hash row is marked on every paper, so this is never the place to
improvise. Two points that earn remarks:

- the digest is what gets **signed**, not the plaintext — so a changed record
  breaks both the hash check and the signature;
- a hash is keyless, so it proves integrity but not origin. If the question
  wants keyed integrity, that is the HMAC switch in 7.14, not this prompt.

---

### 7.8 `signature scheme` — ELGAMAL / RSA / DSA / ECDSA / SCHNORR

| the question says | choose |
| --- | --- |
| "ElGamal signature" | `ELGAMAL` |
| "RSA signature", "signs with its private key" (RSA elsewhere) | `RSA` |
| "DSA", "Digital Signature Algorithm" | `DSA` |
| "ECDSA", "signs on the curve" | `ECDSA` |
| "Schnorr" | `SCHNORR` |
| nothing | `ELGAMAL`, or match whatever the wrap already is |

A signature scheme and a key wrap are **independent choices** — a paper that
wraps with RSA and signs with ElGamal is normal, and the sample paper does
exactly that. Do not "tidy" it into one scheme; the examiner put two there
on purpose.

---

### 7.9 `homomorphic scheme` — PAILLIER / RSA_MUL / ELGAMAL_MUL / NONE

Look for the **verb**, not the scheme name:

| the question's verb | choose | because |
| --- | --- | --- |
| add, total, tally, sum, count, aggregate, average | `PAILLIER` | additively homomorphic: E(a)·E(b) = E(a+b) |
| multiply, product of the encrypted values, scale | `RSA_MUL` or `ELGAMAL_MUL` | multiplicatively homomorphic; pick whichever the question already uses elsewhere |
| **compare** two encrypted values without decrypting | `PAILLIER` | subtract the ciphertexts, decrypt only the difference, look at the sign |
| per-option counts, "how many voted for each candidate" | `PAILLIER` | the generated code packs the counters into one number base-BASE |
| no arithmetic on ciphertext anywhere | `NONE` | saves ~175 lines you would have to explain |

If the question names Paillier **and** says "multiply", trust the scheme
name and treat "multiply" as the ciphertext multiplication that implements
addition — that is the usual phrasing trap.

`NONE` switches off the aggregation menu, the threshold prompt and the
analyst role. Only choose it when nothing in the question touches encrypted
arithmetic.

---

### 7.10 `threshold decryption of the total`, `shares needed`, `shares handed out`

Asked only when a homomorphic scheme is on.

| the question says | answer |
| --- | --- |
| "no single authority can decrypt", "no one party", "requires the cooperation of" | `y` |
| "t-of-n", "2 of 3", "any three of five trustees" | `y`, then those numbers |
| "split the key", "shared among the trustees", "Shamir" | `y` |
| "the election officer decrypts the total" (one named party) | `n` |
| nothing | `y` — it is 57 lines and it is the kind of thing a Remarks column rewards |

Rules for the two numbers:

- `shares needed` (t) ≤ `shares handed out` (n). The wizard will not stop you
  writing 4-of-3; the program will.
- **t = 1** means any single holder can decrypt — that defeats the purpose,
  so never choose it unless the question does.
- **t = n** is additive k-of-k: everybody must be present. Choose it only when
  the question says *all* trustees.
- Silent → **2-of-3**. It is the smallest setting that actually demonstrates
  the property: one share is not enough, two are.

In the demo, show the failure before the success: the analyst menu's
**`3 One share alone`** reconstructs from a single share and prints a value
that is not the private exponent, and then **`2 Reveal total`** decrypts
properly with `t` shares. The failure is the proof — the success on its own
demonstrates nothing a single key would not.

---

### 7.11 `searchable encryption` — SSE / PKSE / NONE

| the question says | choose |
| --- | --- |
| "searchable index", "search without revealing the contents", "locate X without decrypting" | `SSE` |
| "many parties / any hospital / every branch can add to the index", "the index is built with a public key" | `PKSE` |
| "keyword search over encrypted documents" | `SSE` unless it says who writes the index |
| no search anywhere **and** no Search row in the marking table | `NONE` |

**The override that matters:** if the marking table has a **Search** row, turn
search on even when the prose barely mentions it. A marked row left empty is
the most expensive thing you can do in this exam.

What you get either way: a deterministic token per tag (HMAC-SHA256 for SSE,
SHA-256 for PKSE), encrypted values, exact-tag search, time-range search over
one-minute buckets, prefix search, and boolean AND/OR queries. So "search by
constituency **and** by time range" needs no extra setting.

If asked why the tokens are deterministic while the values are randomised:
the server must be able to match a token, so tokens leak equality, and the
number of hits per token leaks how common a tag is. That is the known
weakness. The worked demonstration of it — the **count attack** and
posting-list padding as the mitigation — is in
`IS_Lab_Codebase/Concepts/c15_searchable_encryption.py` and
`Lab8_Searchable_Encryption/additional_questions/q3.py`, not in the generated
answer. Read it once; it is the obvious follow-up question.

---

### 7.12 `access control model` — the seven of Lab 4

Every paper mentions access control somewhere. The question is only *which*
model, and the phrase that decides it is usually five words long.

| choose | the question's giveaway phrase | the one rule that makes it different |
| --- | --- | --- |
| `RBAC` | "roles and permissions", "role-based", a list of actors with actions | a role carries a fixed set of permissions |
| `DAC` | "the **owner** decides who may access", "access matrix", "grant and revoke" | rights are handed over by their holder, and can be taken back |
| `MAC` | "**clearance**", "classification", "security level", "top secret / confidential" | allowed only if clearance ≥ classification, and the action is in the policy |
| `BLP` | "**no read up**", "**no write down**", "Bell-LaPadula", "cannot write to a lower level" | the two properties together: read ≤ own level, write ≥ own level |
| `ABAC` | "**attributes**", "department", "a policy function", "based on the user's properties" | a function of attributes decides, and reports which clause failed |
| `TIME` | "access **expires**", "a licence valid for 30 days", "temporary access", "only during office hours" | a grant carries an expiry and stops working after it |
| `PROB` | "**trust score**", "risk level", "probability of granting", "confidence" | a numeric score is compared against a threshold |

Decision shortcuts:

- The question lists actors and what each may do, and nothing more → `RBAC`.
  That is the common case and the sample paper's case.
- It names **levels** → `MAC`. It names levels **and** restricts writing →
  `BLP`.
- It talks about **who may hand out** a right → `DAC`.
- It talks about **when** → `TIME`.
- It talks about properties that are not levels (department, location,
  device) → `ABAC`.
- Two models fit? Choose the more specific one and say in the write-up that
  it generalises the other: BLP is MAC plus the write rule, ABAC subsumes
  RBAC when the only attribute is a role.

Whichever you choose, the generated demo shows that model's distinctive rule
failing and then succeeding — DAC grants then revokes, BLP refuses a write
down, TIME expires a grant. Run it; it is the quickest access-control
write-up you will get.

---

### 7.13 `key management` (generate / distribute / revoke / renew / rotate, sealed storage)

The biggest single switch: **+184 lines** and a whole extra menu.

| the question says | answer |
| --- | --- |
| "generate, distribute, revoke and renew keys" (the Lab 4 lifecycle verbs) | `y` |
| "a key management service / central authority issues keys" | `y` |
| "keys are renewed every 12 months", "revoke a subsystem's keys" | `y` |
| "private keys must be stored securely" | `y` — the sealed PBKDF2 + AES-GCM store is the cheapest way to show it |
| "a key escrow / audit of key usage" | `y` |
| the question only encrypts and signs | `n` |
| nothing | `n` |

If you turn it on, demo the **revoke** and then the **renew**: a revoked
holder being refused and then restored is the whole point of the lifecycle,
and the generated demo does exactly that.

---

### 7.14 `HMAC tag`, `hash-chained audit log`, `replay protection`

None of these are in the lab manual. All three default to `n`. They are
cheap marks when the paper hints at them and pure liability when it does
not — every switch adds a menu item you must be able to explain.

| prompt | turn it on when the question says | cost |
| --- | --- | --- |
| HMAC tag as well as the digest | "keyed integrity", "MAC", "HMAC", "prove it came from the holder of the key" | +30 lines |
| hash-chain the audit log | "tamper-evident log", "an audit trail that cannot be altered", "append-only", "blockchain-like" | +63 lines |
| reject replayed and stale submissions | "prevent replay", "reject duplicate submissions", "a nonce", "requests older than N seconds" | +57 lines |

The rule: **off unless hinted.** The one exception is when the marking table
has a Remarks column and you finish early — then the hash-chained log is the
most impressive of the three for the least explaining, because you can show
the chain breaking when a line is edited.

An HMAC and a digital signature are not the same thing, and that is the
question that follows if you turn HMAC on: HMAC is symmetric, so both sides
can forge it and it gives integrity without non-repudiation; a signature is
asymmetric, so only the holder of the private key could have made it.

---

### 7.15 `trusted timestamps and a deadline check`

| the question says | answer |
| --- | --- |
| "a timestamp from a trusted authority", "before the deadline", "within the valid period", "office hours", "submitted on time" | `y` |
| you are searching by **time range** | `y` — the time buckets come from the timestamp |
| nothing about time at all | `y` anyway |

Default `y`. It costs 13 lines, it makes the records look real, and
"the submission time is recorded and checked against the deadline" is a
sentence you can write under almost any component.

---

### 7.16 `real TCP client and server`, and `write them as separate files`

| the question says | answer |
| --- | --- |
| "on the client side ... on the server side" | `y` |
| the marking table has a **Client-Server** row | `y`, always |
| "the device submits to the server", "sends over the network" | `y` |
| a single-user tool with no second party | `n` |

Then: **separate files → always `y` when sockets are on.** It is free, it
does not change `answer.py`, and it gives you `answer_server.py` and
`answer_client.py` — two short programs with no comments and nothing they do
not use, which is what you run in two terminals while the examiner watches:

```
terminal 1:  python answer_server.py
terminal 2:  python answer_client.py alice B001 1 101
```

That two-terminal run *is* the Client-Server mark. `netdemo` inside
`answer.py` does the same thing in one process — use it as the backup if a
port is blocked, and say that is what you did.

---

### 7.17 `rename the roles`

Answer `y` and use the question's own actors. The prompt asks for a name per
capability, so map them like this:

| the wizard asks for the role that can | put the question's name for |
| --- | --- |
| `submit` | whoever creates a record — voter, trader, clinic, doctor |
| `verify` | whoever receives and checks it — the server, the commission, the bank |
| `aggregate` | whoever computes on ciphertext — the tally authority, the analyst |
| `view_hashes` | whoever inspects without reading — the auditor, the regulator |

`voter / server / tally / auditor` reads like an answer to this question.
`user1 / user2` reads like a template, and it is the first thing an examiner
notices.

---

### 7.18 `output file name`

Leave it as `answer`. Everything in the instructions, the troubleshooting
table and the commands you have memorised says `answer.py`. Renaming it buys
nothing and costs you the one path you will type fifty times.

---

### 7.19 Everything silent — the safe default build

When the question is vague about everything except the story, this build
answers all five of the usual marked components and nothing more:

```
cipher AES-256   mode CBC     wrap RSA 2048   hash sha512
sign ELGAMAL     he PAILLIER  threshold 2-of-3
search SSE       access RBAC  timestamps y    sockets y + split
kms n            hmac n       log_chain n     replay n
```

That is `python wizard.py --build evoting` with your own four nouns, and it
is 865 lines.

### What each switch costs

Measured against that build, so you can trade size for marks with your eyes
open:

| switch | lines |
| --- | --- |
| key management on | **+184** |
| hash-chained log on | +63 |
| replay protection on | +57 |
| PKSE instead of SSE | +37 |
| HMAC tag on | +30 |
| access TIME / ABAC / DAC / BLP / PROB / MAC instead of RBAC | +58 / +44 / +34 / +25 / +23 / +16 |
| homomorphic off | **−176** |
| sockets off | −95 |
| search off | −71 |
| threshold off | −57 |
| timestamps off | −13 |
| everything optional off (`minimal`) | −362 |

### Before you press Enter on the last prompt

Five seconds, five questions:

1. Does every row of the marking table have a setting that produces it?
2. Is anything on that the question never asked for?
3. Are the four nouns the question's own words?
4. Are the roles the question's own actors?
5. Is `t` ≤ `n`?

---

## 8. Words that look like settings and are not

| the question says | why it changes nothing |
| --- | --- |
| "privacy, verifiability, integrity, non-repudiation" | the four properties the schemes already give you. Use them as the **write-up vocabulary**: hash → integrity, signature → non-repudiation, AES/RSA → confidentiality, Paillier → privacy of individual values |
| "securely", "trusted authority", "remote locations" | scene-setting |
| "ensures data integrity" | the reason for the hash, not a second mechanism |
| "aggregate computations without revealing individual votes" | the definition of homomorphic encryption, restated |
| "databases, files, arrays" | storage already exists — three JSON files |
| "deployed to allow citizens to cast votes" | no |

Rule: a sentence is a setting only if it names a **scheme, algorithm, mode,
key size, or model**. Everything else is prose you will reuse in the
write-up.

---

## 9. When the question asks for something with no setting

It happens. Three cases, in order of what to do:

1. **It is already covered under another name.** "Detects if a record was
   modified" is the hash. "Nobody can deny sending it" is the signature.
   "Only the owner's department can read it" is ABAC. Translate before you
   write code.

2. **A setting gets it with a different value.** "The mode must detect
   tampering" → `mode = GCM`. "Many parties write to the index" → `search =
   PKSE`. "Keys must expire" → `access = TIME`, or `key mgmt = yes`. The
   wording table in `INSTRUCTIONS.md` has 28 of these.

3. **Genuinely not there.** Build everything else, get it running, then add
   the missing piece by hand from
   `IS_Lab_Codebase/Concepts/ALL_CONCEPTS_TOOLKIT.py` — every concept in the
   course is in there as a short standalone function. Paste it under the
   `SETTINGS` block in `answer.py` and wire one menu item to it. Never
   rebuild from scratch for one missing feature.

A working answer missing one bullet scores far better than a complete answer
that does not run. If you are ten minutes from the end with nothing working:
`python wizard.py --build minimal`, run its `demo`, write up what it shows.

---

## 10. A second question, same method

To prove the method is not specific to e-voting — a Lab 4 shaped question:

> *HealthCare Inc. manages patient records across hospitals. Patient data is
> encrypted with AES-128 and the keys are distributed using the Rabin
> cryptosystem. A central key management service generates key pairs,
> distributes them to hospitals, revokes a hospital's keys when it leaves the
> network, and renews all keys every 12 months. Doctors sign readings with
> ECDSA. The system must compare two encrypted readings without decrypting
> them. Access depends on the staff member's clearance level.*

Three passes, same four minutes:

| the phrase | setting |
| --- | --- |
| "patient records", "hospitals", "readings" | record = `record`/`reading`, tag = `hospital`, value = `reading` |
| "AES-128" | `cipher = AES-128` (mode unstated → leave `CBC`, say so) |
| "keys … distributed using the **Rabin** cryptosystem" | `key wrap = RABIN` |
| "sign readings with **ECDSA**" | `signature = ECDSA` |
| "compare two encrypted readings without decrypting" | `homomorphic = PAILLIER` — subtract the ciphertexts, decrypt the difference |
| "generates, distributes, **revokes**, **renews**" | `key mgmt = yes` |
| "depends on the staff member's **clearance level**" | `access = MAC` |
| no hash named | leave `sha512`; the hash row is always marked |
| no search named | `search = NONE`, unless the marking table has a Search row — then turn SSE on anyway |

The nearest preset is `healthcare` (`MediKeys`: RABIN, MAC, key management,
log chain). Start there and change the four lines the question moved:

```
python wizard.py                 # pick scenario: healthcare
  symmetric cipher    AES-128    # preset says AES-256
  signature scheme    ECDSA      # preset says RSA
  homomorphic scheme  PAILLIER   # preset says NONE  -> enables the compare
  searchable          NONE       # unless the marking table has a Search row
```

Four typed lines; Enter accepts the other twenty. That is the normal amount
of work for a question you have not seen before — and it is why you start
from the nearest preset rather than from `custom`.

The point is that you never read the question twice: one pass down the
bullets, one checklist line each.

---

## 11. Blank worksheet — copy this onto the rough sheet

```
MARKED COMPONENTS (from the table at the bottom, in order):
  1 ................  2 ................  3 ................
  4 ................  5 ................  6 ................

NOUNS
  system ...............  one item is a ...............
  searched on ..........  totalled field ..............

SCHEMES
  cipher .......... mode .......... key wrap .......... bits ......
  hash ............ signature .......... homomorphic ..............
  search .......... access ..........

SWITCHES        key mgmt Y/N   threshold Y/N (t-of-n ... of ...)
                timestamps Y/N   sockets Y/N   hmac Y/N
                log chain Y/N   replay Y/N

ROLES (the question's own actors, with the verbs next to each)
  ..................... : ................................
  ..................... : ................................
  ..................... : ................................
  ..................... : ................................

NOT COVERED BY A SETTING -> paste from ALL_CONCEPTS_TOOLKIT.py
  ..............................................................

NEAREST PRESET ..............    ->  python wizard.py --build ........
                                     then fix the lines that differ
```

---

Next: `INSTRUCTIONS.md` step 2 onward — building, running and writing up.
`python wizard.py --options` lists every value every setting accepts.
