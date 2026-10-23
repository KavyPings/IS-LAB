# The end-sem wizard — exam procedure

Labs 1–8. Read this once before the exam; follow it during.

Everything is run **from the IS Lab folder**:

```
cd "C:\Users\kavyk\OneDrive\Desktop\Projects\IS Lab"
```

`wizard.py`, `endsheet.py` and `playsheet.py` there are the same launcher —
use whichever name you remember. `python wizard.py --help` prints a short
version of this file.

On a machine that has never run this folder — a lab PC, a fresh laptop, a USB
copy — **start at Step 0**: it installs Python if needed, makes the venv and
the one library, and proves the folder works.

| file | what it is for |
| --- | --- |
| `READING_THE_QUESTION.md` | step 1 in full: the sample paper decoded, sentence by sentence |
| this file | the five steps, start to finish |
| `../MANUAL_COVERAGE.md` | the audit of all three lab manuals against the wizard's options |

---

## Step 0 — set up from nothing

Do this on any machine that has not run the folder before: a lab PC, a fresh
laptop, a USB copy. Four minutes.

### 0.1 Is Python installed?

```
python --version          # Windows
python3 --version         # macOS / Linux
```

3.8 or newer is fine. If the shell says *not recognized* / *command not
found*, install it:

| | |
| --- | --- |
| Windows | `winget install Python.Python.3.12` — or python.org, and **tick "Add python.exe to PATH"** in the installer |
| macOS | `brew install python` |
| Linux | `sudo apt install python3 python3-venv python3-pip` |

Close and reopen the terminal after installing, or PATH will not have
updated.

### 0.2 Get the folder onto the machine

Copy the whole **IS Lab** folder. A short path with no OneDrive in it is
preferable (`C:\IS Lab` or `~/IS Lab`) — OneDrive adds nothing here and can
lock files mid-run.

These must come with it:

```
wizard.py  endsheet.py  playsheet.py     the launchers (same program, 3 names)
islab.py   pylib/                        the locked-down-machine rescue
checkup.py                               the self test
Wizards/                                 both wizards and these docs
IS_Lab_Codebase/                         per-lab answers, Concepts/, cheatsheets
```

Nothing else is needed to build an answer. `.venv/`, `answer*.py`,
`*.json`, `*.pem`, `*.log` and `checkup_report.txt` are all generated — do
not bother copying them, and delete them if they came along.

### 0.3 Open a terminal in that folder

The path has a space in it, so it needs quotes:

```
cd "C:\Users\<you>\Desktop\IS Lab"        # Windows
cd ~/Desktop/"IS Lab"                     # macOS / Linux
```

On Windows, Shift + right-click the folder → *Open PowerShell window here*
does the same thing.

### 0.4 Virtual environment

```
# Windows PowerShell
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Windows cmd
python -m venv .venv
.venv\Scripts\activate.bat

# macOS / Linux
python3 -m venv .venv
source .venv/bin/activate
```

The prompt gains `(.venv)`. That is the only confirmation.

| problem | fix |
| --- | --- |
| PowerShell: *running scripts is disabled on this system* | use `cmd` instead, or run once: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` |
| Linux: `No module named venv` | `sudo apt install python3-venv` |
| `python` works but `python -m venv` writes nothing | you are on the Microsoft Store stub; install from winget or python.org |

The venv is **optional** — everything runs against a plain global install
too. It is worth two minutes because it keeps the lab machine clean and is a
free sentence in the write-up.

### 0.5 Install the one library

```
python -m pip install --upgrade pip
python -m pip install pycryptodome
```

That is the whole dependency list. No `cryptography`, no `numpy`, no
`sympy` — the mid-sem wizard used to need `cryptography` and no longer does.

**If pip is blocked or there is no network:** skip this step entirely. The
pure-Python backend in `pylib/` covers AES-128/192/256, DES, 3DES, every
mode including GCM and EAX, the SHA family, MD5, RSA, OAEP and ECC with
nothing installed, and `wizard.py` switches to it by itself. The outputs are
byte-identical; only the speed differs.

**To carry the fast path offline**, do this beforehand on a machine with
network, and bring the `wheels` folder:

```
pip download pycryptodome -d wheels
# then, on the exam machine:
python -m pip install --no-index --find-links wheels pycryptodome
```

**Never install `crypto` or `pycrypto`.** Both create a `Crypto` package
that shadows pycryptodome and breaks every import. If one is already there:

```
python -m pip uninstall crypto pycrypto
python -m pip install --force-reinstall pycryptodome
```

### 0.6 Prove it works

```
python wizard.py --check
```

Must end with `ENVIRONMENT READY`. The `backend` line says `native` or
`pure` — either is fine.

Then, once, while there is no time pressure:

```
python checkup.py
```

About three minutes. It tests the environment, known-answer vectors (FIPS-197
AES, the manual's DES example, RFC 4493 CMAC, the sample paper's SHA-512),
both wizards, every preset, the menus, the TCP path, every per-lab file and
the full option matrix, and writes `checkup_report.txt`. Run it the day
before, not in the exam.

`python checkup.py quick` is a 20-second version. `python checkup.py tidy`
moves generated junk into `_to_delete/<date>/` — it never deletes anything.

### 0.7 Every session after the first

Only the activate line:

```
.\.venv\Scripts\Activate.ps1      # Windows
source .venv/bin/activate         # macOS / Linux
```

Forgetting it is the single most common error in the exam:
`ModuleNotFoundError: No module named 'Crypto'`.

---

## Step 1 — read the question (10 minutes, no typing)

**`READING_THE_QUESTION.md`, next to this file, is this step in full** — the
sample paper taken apart sentence by sentence, the three-pass method, the
marking table read first, and a blank worksheet. Read that one before the
exam. What follows here is the short version.

Copy this onto the rough sheet and fill it in. Each line is one wizard answer.

```
cipher ....... mode ....... key wrap ....... hash .......
signature ....... homomorphic ....... search ....... access .......
key mgmt Y/N   threshold Y/N   timestamps Y/N   sockets Y/N
hmac Y/N   log chain Y/N   replay Y/N
roles ............................................................
one record is called ......  searched on ......  totalled field ......
```

What the wording means:

| the question says | it sets |
| --- | --- |
| "AES-256 in CBC mode", "DES", "3DES" | cipher, mode |
| "authenticated encryption", "the mode detects tampering" | mode = GCM or EAX |
| "encrypt the AES key with the RSA public key" | key wrap = RSA |
| "ECC", "secp256r1", "ECIES" | key wrap = ECC |
| "ElGamal with public key (p, g, h)" | key wrap = ELGAMAL |
| "Rabin cryptosystem" | key wrap = RABIN |
| "Diffie-Hellman", "shared secret over an insecure channel" | key wrap = DH |
| "SHA-512 / 256 / SHA-3 / MD5" | hash |
| "write your own hash function", "5381", "multiply by 33" | hash = custom |
| "ElGamal / RSA / DSA / ECDSA / Schnorr signature" | signature |
| "tally", "total", "aggregate without revealing individual values" | homomorphic = PAILLIER |
| "product of the encrypted values" | RSA_MUL or ELGAMAL_MUL |
| "searchable index", "locate X without revealing Y" | search = SSE |
| "public key, so many parties can add to the index" | search = PKSE |
| "roles and permissions" | access = RBAC |
| "the owner decides who may access", "access matrix" | access = DAC |
| "clearance", "classification", "security level" | access = MAC |
| "no read up", "no write down", "Bell-LaPadula" | access = BLP |
| "attributes", "department", "policy function" | access = ABAC |
| "limited-time access", "licence", "expires" | access = TIME |
| "trust level", "risk", "probability of access" | access = PROB |
| "generate, distribute, revoke, renew keys", "rotation", "secure storage of private keys" | key mgmt = yes |
| "no single authority may decrypt" | threshold = yes |
| "trusted timestamp", "before the deadline" | timestamps = yes |
| "client side … server side" | sockets = yes |
| "integrity and authenticity from a shared secret" | hmac = yes |
| "detailed logs for auditing", "tamper-evident" | log chain = yes |
| "replay", "freshness", "nonce" | replay = yes |
| "menu driven" | not optional — see step 4 |

Also find the **marking table** at the bottom of the paper and copy the
component names down. That list, not the story, is what you are scored on.

---

## Step 2 — build it (2 minutes)

```
python wizard.py
```

Press Enter for anything the preset already has right. The first question
picks the closest scenario:

| preset | when the question looks like |
| --- | --- |
| `evoting` | voting, tallying, threshold — the sample paper |
| `trade` | financial reports, totals, RSA signatures |
| `medical` | patient records, ECDSA, comparing readings |
| `banking` | transactions, DSA, multiplicative RSA |
| `documents` | a document archive with search, no homomorphic part |
| `healthcare` | HealthCare Inc. — Rabin keys, key management (Lab 4 Q2) |
| `drm` | DigiRights — ElGamal, licences that expire (Lab 4 additional) |
| `enterprise` | SecureCorp — RSA + Diffie-Hellman between subsystems (Lab 4 Q1) |
| `everything` | practice: every component on at once |
| `minimal` | smallest answer that still earns ED + DSS + Hash |
| `custom` | nothing fits; set every option yourself |

The last four come straight out of the Lab 4 questions, so a reworded
SecureCorp / HealthCare / DigiRights paper starts there.

No questions at all: `python wizard.py --build evoting`.
Every accepted value: `python wizard.py --options`.

---

## Step 3 — what you now have

| file | what it is | use it for |
| --- | --- | --- |
| `answer.py` | the answer, menu driven, with comments | read it, explain it, run it |
| `answer_clean.py` | same program, comments stripped | the code listing you attach |
| `answer_server.py` | the server half alone, no comments | terminal 1 |
| `answer_client.py` | the client half alone, no comments | terminal 2 |

The two halves are assembled from the same tested code as `answer.py`, then
everything each half never calls is removed and every comment stripped — so
they come out around a quarter of the size and contain nothing you would have
to explain away. They import nothing from each other; each is a complete
program with its own entry point.

The sample paper asks for *"a menu-driven Python program"* and its own menu is
`1 Voter | 2 Election Server | 3 Tally Authority`, so **`answer.py` is the
answer**. The halves exist for an examiner who wants to see a client and a
server as two programs, the way the Lab 5 and Lab 6 socket questions are
written. Answer `n` to *"also write the client and server as separate files"*
if you do not want them.

---

## Step 4 — run it (20 minutes)

```
python answer.py demo
```

Let it run once, uninterrupted. It submits records, verifies them, searches,
tampers, aggregates, reveals, shows the access model refusing something, and
prints the audit log. If anything is wrong you see it here, before the
examiner does.

Then the part that is actually marked:

```
python answer.py
```

**The paper halves the total if the program is not menu driven.** Click
through every item while the examiner watches, and point at these:

| component | what to show |
| --- | --- |
| Client-Server | submit on the client menu, verify on the server menu, then `netdemo` — or the two halves in two terminals |
| ED | the IV line, the ciphertext line, the wrapped-session-key line |
| DSS | `signature valid`, then `INVALID` after the tamper test |
| Hash | the digest, then `DOES NOT MATCH` after tampering |
| Search | search by tag and by time range, and say the server matched tokens only |
| Lab 7 | aggregate, then reveal, and say no single record was decrypted |
| threshold | the "one share alone" menu item |
| access control | the ACCESS DENIED line, and the policy table from the auditor menu |
| key management | the key-management menu: list, distribute, revoke, renew, rotate |
| storage | open `records.json` and show it is all ciphertext |
| audit | print the log; with the chain on, verify it |

Two terminals:

```
terminal 1:  python answer_server.py
terminal 2:  python answer_client.py alice B001 1 101
             python answer_client.py                   (asks for the fields)
```

The server prints the key unwrap, the signature check, the hash comparison
and the timestamp check for every record it receives.

---

## Step 5 — the write-up (5 marks)

One short paragraph per marked component. The pattern that scores: **what**
was used, **where** in the program, **why** that choice, and what it does
**not** give you. For example:

> The record is encrypted with AES-256 in CBC mode (`encrypt_data`), with a
> fresh random IV per record so two identical records give different
> ciphertexts. The AES key is a one-time session key, wrapped with the
> server's RSA-2048 public key using OAEP (`wrap_key`), which removes the need
> for a pre-shared secret. AES gives confidentiality only — integrity comes
> from the SHA-512 digest and authenticity from the signature.

Sentences worth having ready:

* **Why hash before signing** — the signature operation has a fixed input
  size, and raw RSA signatures are malleable.
* **Why hybrid encryption** — RSA cannot encrypt a long record and symmetric
  encryption cannot solve key distribution; using both solves both.
* **Why Paillier and not RSA for a tally** — RSA multiplies, a tally needs
  addition. Paillier is the only scheme in the syllabus where multiplying the
  ciphertexts adds the plaintexts.
* **Why the search index key is deterministic** — a randomised ciphertext
  would never match a query. That determinism is also the scheme's main
  leakage, and saying so is a mark.
* **What the server still learns** — how many records exist, which token was
  queried, when records arrived. Never the content.
* **Why threshold decryption** — the private exponent never exists in one
  place, so no single authority can read the result.
* **Why HMAC and not just a hash** — whoever edits the record can recompute a
  plain digest; they cannot recompute a keyed tag.
* **Why a hash-chained log** — each entry carries the hash of the one before,
  so removing or editing any entry breaks the chain from there on.
* **What this is not** — not a production system: no coercion resistance, no
  anonymity from the server, no verifiable shuffle, and the leakage above.

---

## Changing the answer instead of rebuilding it

The top of `answer.py` is a settings block:

```python
# ===== SETTINGS - change these to match the question =====
system_name  = "..."
record_word  = "..."
roles        = { ... }        copy the question's bullet points here
key_bytes    = 32             16 = AES-128, 24 = AES-192, 32 = AES-256
rsa_bits     = 2048           4096 if the question insists
window_opens / window_closes  the deadline
clearance / classification / access_matrix / time_grants / trust_level
kms_passphrase / kdf_iterations / key_lifetime_days
threshold_t / threshold_n
# ===== END SETTINGS =====
```

Nothing below it needs touching for a different key size, role set, deadline,
clearance level or threshold. Two worth doing deliberately:

* **roles** — copy the question's bullet points verbatim. That one dict is the
  whole access-control mark.
* **window_closes** — set it to a past time for one submission to demonstrate
  a rejected late record, then set it back.

Files a run creates, all removed by `python answer.py reset`:

```
records.json  index.json  numbers.json  keys.json  kms_keys.json
he_key.json   pkse_key.json   server_private.pem  server_public.pem
server_key.json   audit.log
```

---

## Making the listing shorter

If the examiner wants less code, delete from `answer_clean.py` in this order.
Each step is independently safe:

1. the `Client-Server over TCP` section and the `netdemo` / `server` /
   `client` branches — only if the question has no client-server part.
2. `one_share_alone()` and its menu entry — a demonstration, not a requirement.
3. two of `show_hashes` / `view_own` / `view_all` — keep one, the auditor role
   needs something to do.
4. `demo()` — but only after the examiner has seen it run.

Never delete `check_permission` (the access-control mark), `log_action` (the
audit trail), or any function behind one of the marked components.

---

## If something breaks

| symptom | fix |
| --- | --- |
| `can't open file '...'` | wrong folder. `cd` into the IS Lab folder |
| `python` not recognized | Python is not on PATH — Step 0.1 |
| `Activate.ps1 cannot be loaded` | PowerShell execution policy — Step 0.4 |
| `ImportError: cannot import name ... from 'Crypto'` | `crypto` or `pycrypto` is installed and shadowing pycryptodome — Step 0.5 |
| `ModuleNotFoundError: Crypto` | the venv is not active, or `pip install pycryptodome` |
| `OSError: Cannot load native module ... 0x11c7` | an Application Control policy. `python wizard.py` loads the fallback in `pylib/` itself; see `pylib/README.md` |
| RSA-4096 keygen is slow | `rsa_bits = 2048`; say in the write-up that only the key size changes |
| `ValueError: Padding is incorrect` | wrong key, or the record was tampered with — which is the point of the tamper test |
| `MAC check failed` | a GCM/EAX tag did not verify: tampering, or the wrong nonce |
| the wizard will not build | `python wizard.py --build minimal` always works, then paste what is missing from `IS_Lab_Codebase/Concepts/ALL_CONCEPTS_TOOLKIT.py` |
| ten minutes left, nothing runs | build `minimal`, run its `demo`, write up what it shows. Four working components beat five broken ones |

---

## Coverage

`Wizards/MANUAL_COVERAGE.md` is the audit of all three lab manuals against
these options — what is covered, and the two places where the manual's own
listings do not run (Lab 7's ElGamal "comparison" and Lab 8's index keys).
Spotting those in the viva is worth more than copying them.
