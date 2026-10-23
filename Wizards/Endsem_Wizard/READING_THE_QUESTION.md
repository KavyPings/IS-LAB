# Reading the question

How to turn an end-sem question into a filled checklist in ten minutes,
using the sample paper as the worked example.

The question looks long. It is not. Every end-sem question in this course is
the **same question** with the nouns changed — an e-voting system, a trade
reporting system, a hospital record system — and the scheme names swapped.
Your whole job in the first ten minutes is to find which scheme name went
into each slot. Nothing else in the question needs a decision.

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

## 7. What to type

This exact configuration is the `evoting` preset, so in the exam it is one
line:

```
python wizard.py --build evoting
```

But **check the preset against your checklist before trusting it** — the
real paper will differ somewhere. If it does, run the questions instead:

```
python wizard.py
```

and the prompts come in checklist order: scenario → the four nouns → cipher,
mode, key wrap, RSA size → hash, signature → homomorphic, threshold, search
→ access model → key management → hmac / log chain / replay → timestamps,
sockets, split → roles → output name. Enter accepts the shown default, so
starting from the nearest preset means you only type the lines that changed.

Either way you get four files. `answer.py` is the answer.

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
