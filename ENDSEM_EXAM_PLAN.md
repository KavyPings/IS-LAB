# End-sem exam plan — ICT 3141 Information Security Lab

20 marks, 90 minutes, Labs 1–8. Write-up 5, execution 15.
**If the program is not menu driven the total is halved.**

Read `START_HERE.md` first if you have not. This file is the minute-by-minute
plan.

---

## The time budget

| | minutes | what |
| --- | --- | --- |
| Phase 0 | before the exam | environment, done once |
| Phase 1 | 0–10 | read the question, fill in the decision list |
| Phase 2 | 10–20 | build the answer |
| Phase 3 | 20–35 | check the configuration against the question |
| Phase 4 | 35–55 | run it, demonstrate every component |
| Phase 5 | 55–90 | the write-up, and the viva |

If anything goes wrong, Phase 4 is the one to protect. A working demo of four
components beats a half-written program with five.

---

## PHASE 0 — setup (do this before the exam, not during it)

1. **Go to the folder first.** Every command below assumes you are standing
   in the IS Lab folder. Running them from the Desktop is the one mistake
   that wastes exam minutes:

   ```
   cd "C:\Users\kavyk\OneDrive\Desktop\Projects\IS Lab"
   ```

2. **Virtual environment**

   ```
   python -m venv .venv
   .venv\Scripts\activate              # Windows
   source .venv/bin/activate           # macOS / Linux
   ```

   The prompt should now start with `(.venv)`.

3. **Install the one library**

   ```
   pip install pycryptodome
   ```

   Nothing else. No `phe`, no NumPy, no network.

4. **Check**

   ```
   python wizard.py --check
   ```

   The `backend` line says whether pycryptodome's compiled modules load or
   whether the pure-Python fallback in `pylib/` is standing in for them.
   Either is fine; the output is byte-identical.

   Must print `ENVIRONMENT READY`. `wizard.py` sits in the IS Lab folder and
   finds the real wizards inside `Wizards/` itself, so you never type the
   long path. Every flag is passed straight through to it.
   `python endsheet.py --check` from the same folder does exactly the same
   thing, if that is the name you remember.

5. **Prove it end to end**

   ```
   python wizard.py --build evoting
   python answer.py demo
   python answer.py
   python answer.py reset
   ```

   Click through every menu item once. You now know what the output looks
   like, which is most of the exam.

6. **Optional, once:** `python checkup.py` tests everything in the folder —
   environment, crypto backend, known-answer vectors, both wizards, all six
   presets, the menus, the TCP path, every per-lab question file and both
   wizard self-tests — and writes `checkup_report.txt`. `python checkup.py
   quick` skips the two slow self-tests.

7. **The escape hatch.** If the wizard ever refuses to build:
   `python wizard.py --build minimal` always works, and
   `IS_Lab_Codebase/Concepts/ALL_CONCEPTS_TOOLKIT.py` has every function in
   Labs 1–8 ready to paste.

Checklist: [ ] in the IS Lab folder  [ ] venv active  [ ] pycryptodome
installed  [ ] `--check` green  [ ] `demo` run once  [ ] menu clicked through
[ ] `reset` works

---

## PHASE 1 — read the question (10 minutes, no typing)

Copy this list onto the rough sheet and fill it in from the question text.
Every row maps to one wizard answer.

```
cipher        AES-128 / AES-192 / AES-256 / DES / 3DES   ......
mode          CBC / ECB / CFB / OFB / CTR / GCM / EAX    ......
key wrap      RSA / ECC / ElGamal / Rabin / DH / none    ......
hash          SHA-512 / 384 / 256 / 224 / SHA-1 / SHA-3 / MD5 / custom
signature     ElGamal / RSA / DSA / ECDSA / Schnorr      ......
homomorphic   Paillier (total) / ElGamal or RSA (product) / none
search        SSE / PKSE / none                          ......
access        RBAC / DAC / MAC / BLP / ABAC / TIME / PROB ......
key mgmt      generate, distribute, revoke, renew, rotate? yes / no
threshold     yes (t of n?) / no                         ......
timestamps    yes (deadline?) / no                       ......
client-server sockets / one process                      ......
HMAC tag      yes / no        hash-chained log  yes / no
replay check  yes / no
roles         ............ / ............ / ............
record        what is one stored item called?            ......
tag field     what is searched on?                       ......
value field   what numeric field gets totalled?          ......
```

Words to watch for:

| the question says | it means |
| --- | --- |
| "tally", "total", "aggregate without revealing individual…" | Paillier |
| "product of the encrypted values" | ElGamal or textbook RSA |
| "searchable index", "locate X without revealing Y" | SSE |
| "encrypted with the public key so many parties can index" | PKSE |
| "no single authority can decrypt" | threshold, Shamir t-of-n |
| "trusted timestamp", "before the deadline" | timestamps |
| "client side … server side" | sockets |
| "Rabin cryptosystem" | key wrap = RABIN (Lab 4 Q2) |
| "Diffie-Hellman shared secret" | key wrap = DH (Lab 3 Q5) |
| "ElGamal with public key (p, g, h)" | key wrap = ELGAMAL (Lab 3 Q3) |
| "your own hash function", "5381", "x33" | hash = custom (Lab 5 Q1) |
| "clearance" / "no read up" / "attributes" / "limited-time" / "trust level" | the matching access model |
| "generate, distribute, revoke, renew", "secure storage of private keys" | key management = yes (Lab 4 Q1/Q2) |
| "menu driven" | it is not optional |

All seven access-control models from Lab 4 and the full key-management
catalogue are wizard options — `python wizard.py --options` lists every value.

Also find the **marking table** at the bottom of the paper and write the
component names down. In the sample paper they are Client-Server, ED, DSS,
Hash, Search. That list, not the story, is what gets marked.

---

## PHASE 2 — build (10 minutes)

```
python wizard.py
```

Answer with the list from Phase 1; press Enter for anything unchanged. The
first question picks the closest preset:

| preset | when |
| --- | --- |
| `evoting` | voting, tallying, threshold — the sample paper |
| `trade` | financial reports, totals, RSA signatures |
| `medical` | patient records, ECDSA, comparing readings |
| `banking` | transactions, DSA, multiplicative RSA |
| `documents` | a document archive with search, no homomorphic part |
| `minimal` | smallest answer that still earns ED + DSS + Hash |
| `custom` | nothing fits; set every option yourself |

It writes two files:

* `answer.py` — with comments. Read this; it is how you explain the code.
* `answer_clean.py` — comments stripped, section banners kept. This is the
  listing to attach as the output.

Both are parsed before being written, so if a file exists it runs.

---

## PHASE 3 — check the configuration (15 minutes)

Open `answer.py` and look only at the top:

```python
# ===== SETTINGS - change these to match the question =====
system_name  = "..."        the name on the menu
record_word  = "..."        ballot / report / transaction / document
roles        = { ... }      copy the role bullet points from the question
key_bytes    = 32           16 = AES-128, 24 = AES-192, 32 = AES-256
rsa_bits     = 2048         set 4096 if the question insists
sign_bits    = 256          size of the ElGamal / Schnorr prime
paillier_bits= 512          size of the Paillier modulus
threshold_t  = 2            shares needed
threshold_n  = 3            shares handed out
window_opens = "..."        earliest accepted timestamp
window_closes= "..."        the deadline
categories   = { ... }      option id -> name, for the tally output
host, port   = ...
# ===== END SETTINGS =====
```

Nothing below that block needs to change for a different key size, role set,
deadline or threshold. Two things worth doing deliberately:

* **roles** — copy the question's bullet points verbatim into the dict. That
  single dict is the whole access-control mark.
* **window_closes** — set it to a time in the past for one submission, so you
  can demonstrate a rejected late record. Then set it back.

Files the program creates when it runs (all removed by `python answer.py reset`):

```
records.json        the stored envelopes
index.json          the encrypted search index
keys.json           the signer keys
he_key.json         the homomorphic key pair
server_private.pem  server_public.pem
audit.log
```

---

## PHASE 4 — run and demonstrate (20 minutes)

```
python answer.py demo
```

Let it run once, uninterrupted. It prints, in order: three records submitted
with every intermediate value, each one verified, the searches, a tamper test,
the aggregate, the threshold reveal, the auditor view, two ACCESS DENIED
lines, the TCP exchange, and the audit log.

Then the part that is actually marked:

```
python answer.py
```

and click through it. Point at these as you go:

| component | what to show |
| --- | --- |
| Client-Server | submit on the client menu, verify on the server menu, then `netdemo` — or `answer_server.py` and `answer_client.py` in two terminals |
| ED | the IV line, the ciphertext line, the wrapped-session-key line |
| DSS | `signature valid`, then `INVALID` after tampering |
| Hash | the digest, then `DOES NOT MATCH` after tampering |
| Search | search by tag and by time range, and say the server matched tokens only |
| Lab 7 | aggregate, then reveal, and say no single record was decrypted |
| threshold | the "one share alone" menu item |
| access control | an ACCESS DENIED line |
| storage | open `records.json` and show it is all ciphertext |
| audit | print the log |

For a two-terminal client/server demonstration, either shape works:

```
terminal 1:  python answer.py server          one file, two modes
terminal 2:  python answer.py client

terminal 1:  python answer_server.py          two separate programs
terminal 2:  python answer_client.py alice B001 1 101
```

The wizard writes `answer_server.py` and `answer_client.py` alongside the
answer whenever the question has a client-server part. Each is the complete
answer with a different entry point — nothing is imported between them — so
you can show whichever the examiner expects. Full detail in
`Wizards/Endsem_Wizard/INSTRUCTIONS.md`.

---

## PHASE 5 — the write-up (5 marks)

One short paragraph per marked component. The pattern that scores:

> **what** was used, **where** in the program, **why** that choice, and what
> it does **not** give you.

Example, for ED:

> The record is encrypted with AES-256 in CBC mode (`encrypt_data`), with a
> fresh random IV per record so identical records give different ciphertexts.
> The AES key is a one-time session key, wrapped with the server's RSA-2048
> public key using OAEP (`wrap_key`), which removes the need for a pre-shared
> secret. AES gives confidentiality only — integrity comes from the SHA-512
> digest and authenticity from the signature.

Sentences worth having ready:

* **Why hash before signing** — the signature operation has a fixed input
  size, and raw RSA signatures are malleable.
* **Why hybrid encryption** — RSA cannot encrypt a long record, and symmetric
  encryption cannot solve key distribution. Using both solves both.
* **Why Paillier and not RSA for the tally** — RSA multiplies, a tally needs
  addition. Paillier is the only scheme in the syllabus where multiplying the
  ciphertexts adds the plaintexts.
* **Why the search index key is deterministic** — a randomised ciphertext
  would never match a query. That determinism is also the scheme's main
  leakage, and should be stated.
* **What the server still learns** — how many records exist, which token was
  queried, and when records arrived. Never the content. Saying this out loud
  is a mark, not an admission.
* **Why threshold decryption** — the private exponent never exists in one
  place, so no single authority can read the result.
* **What this is not** — not a production system: no coercion resistance, no
  anonymity from the server, no verifiable shuffle, and the leakage above.

---

## If something breaks mid-exam

| symptom | fix |
| --- | --- |
| `can't open file '...': No such file or directory` | you are not in the IS Lab folder. `cd` into it — from there `python wizard.py` and `python endsheet.py` both work |
| `ModuleNotFoundError: Crypto` | the venv is not active; activate it or `pip install pycryptodome` |
| `OSError: Cannot load native module 'Crypto.Hash._SHA1' ... error 0x11c7` (or `WinError 4551`) | an Application Control policy is blocking pycryptodome's compiled files. Nothing to install. Run `python wizard.py` — it loads the pure-Python fallback in `pylib/` — and read `pylib/README.md` |
| RSA-4096 keygen is slow | set `rsa_bits = 2048`, say in the write-up that only the key size changes |
| `PermissionError` on reset (Windows) | a file handle is open; use a new record id instead of resetting |
| `ValueError: Padding is incorrect` | you decrypted with the wrong key, or the record was tampered with — which is the point of the tamper test |
| `Traceback` in a generated file | it is plain Python with no magic; the traceback names one function |
| the wizard will not build | `python wizard.py --build minimal`, then paste what is missing from `ALL_CONCEPTS_TOOLKIT.py` |
| 10 minutes left and nothing runs | run `python wizard.py --build minimal`, run its `demo`, and write up what it shows. Four working components beat five broken ones. |

---

## Making the answer shorter

If the examiner wants a smaller listing, delete from `answer_clean.py` in this
order. Each step is independently safe.

1. the `Client-Server over TCP` section and the `netdemo` / `server` /
   `client` branches — only if the question has no client-server component.
2. `one_share_alone()` and its menu entry — a demonstration, not a requirement.
3. two of `show_hashes` / `view_own` / `view_all` — keep one, the auditor role
   needs something to do.
4. `demo()` — but only after the examiner has seen it run.

Never delete `check_permission` (the access-control mark), `log_action` (the
audit trail), or any function behind one of the five marked components.

---

## Coverage check — the manual against the codebase

| manual | topic | where |
| --- | --- | --- |
| Lab 1 | classical ciphers, brute force | `Concepts/c01`, `Lab1_*` |
| Lab 2 | DES, 3DES, AES, five modes, key expansion | `Concepts/c02`, `Lab2_*` |
| Lab 3 | RSA, ElGamal, ECC, Diffie-Hellman | `Concepts/c03`–`c05`, `c07`, `Lab3_*` |
| Lab 4 | Rabin, key management, access control, weak-key attacks | `Concepts/c06`, `c10`, `c11`, `Lab4_*` |
| Lab 5 | hashing, custom hash, HMAC, collisions, sockets | `Concepts/c08`, `c13`, `Lab5_*` |
| Lab 6 | RSA / DSA / ECDSA / ElGamal / Schnorr signatures | `Concepts/c09`, `c04`, `Lab6_*` |
| Lab 7 | Paillier, RSA and ElGamal homomorphism, thresholding, benchmarking, secure diagnosis | `Concepts/c14`, `c16`, `Lab7_*` |
| Lab 8 | SSE, PKSE, GnuPG, Snort, leakage | `Concepts/c15`, `Lab8_*` |
| end-sem sample | all of the above in one menu-driven program | `Endsem_Sample_Question_Answer/evoting.py` |

Two places where the manual's own listings do not work, and what to write
instead — both are explained in the file headers:

* **Lab 7 ElGamal "homomorphic comparison"** — multiplying ElGamal
  ciphertexts multiplies the plaintexts; there is no ordering information in
  the result, and the listing does not run. Use Paillier subtraction and
  publish only the sign. `Lab7_Homomorphic_Encryption/additional_questions/q5.py`
* **Lab 8 SSE and PKSE index keys** — both listings use a randomised
  ciphertext as the index key, so no query ever matches. Use a deterministic
  token for the key and randomised encryption for the values.
  `Lab8_Searchable_Encryption/exercise_questions/q1.py` and `q2.py`

Spotting these in the viva is worth more than copying the manual.
