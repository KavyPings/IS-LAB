# Exam Day Plan — `playsheet.py`

**22 blocks · 13 ciphers · 4 signature schemes · self-test 153/153 passing · Lab 1–6 of the manual fully covered.**

Nothing in your answer file imports from the playsheet. Every block is copy-paste source code.

**Every build writes two files.** `answer.py` keeps all the comments — that's yours to read and reconfigure. `answer_clean.py` is the identical program with comments and docstrings stripped — that's the one you show. Both are verified to run identically.

**All answers print in hexadecimal** — ciphertext, hashes and signatures. Big numbers (ElGamal, Schnorr) are stored and shown as hex rather than enormous decimal strings. Classical ciphers still show their letters, because that *is* the answer, with the hex on the line below.

The wizard writes a **lean** answer file — **387 lines commented, 359 clean** — containing only the cipher, hash and signature scheme the question actually asks for. It is written flat and plain: top-to-bottom functions, module-level settings, ordinary `print()` output, no class wrapping everything and no helper layer. The full version is still one flag away when you need the extras.

---

# PHASE 0 — Setup (do this the night before, and again in the 15-minute window)

### Step 1 — Make a virtual environment

A venv keeps the crypto libraries in your folder instead of fighting whatever Python the lab machine has.

```bash
cd <your working folder>
python -m venv .venv
```

Activate it. **Every new terminal needs this line** — if your prompt doesn't start with `(.venv)`, it isn't active:

| Shell | Command |
|---|---|
| Windows PowerShell | `.venv\Scripts\Activate.ps1` |
| Windows cmd.exe | `.venv\Scripts\activate.bat` |
| mac / Linux | `source .venv/bin/activate` |

If PowerShell refuses with a script-execution error:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```
then activate again.

Can't make a venv at all? Skip it — everything works system-wide too.

### Step 2 — Install the libraries (while the internet is on)

```bash
python playsheet.py --setup
```

Installs `pycryptodome`, `cryptography`, `matplotlib`, then re-runs the check. If it fails:

```bash
python -m pip install --upgrade pip
python -m pip install pycryptodome cryptography matplotlib
# if pip says "externally managed environment":
python -m pip install --break-system-packages pycryptodome cryptography
```

> Install **`pycryptodome`**, never `pycrypto`. Both import as `Crypto`, which is exactly why people lose twenty minutes to this.

`python playsheet.py --venv` prints all of this back at you if you forget.

### Step 3 — Environment check

```bash
python playsheet.py --check
```

Want **RESULT: READY**. It reports the interpreter path, whether the venv is active, both crypto libraries, socket binding and file-write permission.

### Step 4 — Prove the code works on this machine

```bash
python playsheet.py --selftest
```

Want **153/153 passed**. Runs every cipher, every mode, every signature scheme, the sockets, the attacks, the scenario template, and builds + runs 19 lean answer files end to end — checking each one actually detects tampering, including two re-run on a cp1252 console to catch Windows encoding crashes. If something is broken you find out now, not 40 minutes in.

### Step 5 — Build one answer file and run it

Do a full dry run now, so nothing is new later.

```bash
python playsheet.py --wizard
```

Answer the nine questions (defaults are fine), then check what it produced:

```bash
python answer.py demo          # the commented file
python answer_clean.py demo    # the stripped file — same output
```

Both must print `INTEGRITY : OK`, then `FAILED - record modified` after the tamper step. Delete `answer.py`, `answer_clean.py`, `records.json`, `keys/` and `audit.log` afterwards.

### Step 6 — Know the one-line escape hatch

If anything goes wrong later, this rebuilds from scratch in about two seconds:

```bash
python playsheet.py --lean DES -o answer.py
```

**Checklist before the paper arrives**
- [ ] `(.venv)` in the prompt
- [ ] `--check` says READY
- [ ] `--selftest` says 153/153
- [ ] you've run `--wizard` once and know the nine questions
- [ ] you've run both `answer.py demo` and `answer_clean.py demo`
- [ ] you know where `playsheet.py` is

---

# PHASE 1 — Read the question (2 minutes)

### Step 1 — Extract five things and write them in the margin

| Question says | You need |
|---|---|
| "DES / AES / Triple DES" | `cipher` + `mode` |
| "Hill / Vigenère / Playfair / Caesar / affine" | `cipher` + `key` |
| "RSA / ElGamal / ECDSA / Schnorr signatures" | `signature` |
| "SHA-256 / MD5 / SHA-512" | `hash` |
| the user types (Student, Doctor, Manager…) | `ROLES` |

### Step 2 — Decide lean or full

**Does the question ask for anything beyond encrypt → hash → sign → roles?** Sockets, key revocation/renewal, Bell-LaPadula, cryptanalysis, Diffie-Hellman, Rabin, ECC, performance graphs, AES round keys.

- **No** → lean. Skip question 9 in the wizard.
- **Yes** → full. Pick the extras at question 9 and the wizard switches automatically.

### Step 3 — Note the exact key from the question

Copy it character for character, including case. A short key is zero-padded and a long one truncated, so a wrong length will not crash you — but the examiner is checking the key.

---

# PHASE 2 — Build the answer file (1 minute)

### Step 1 — Run the wizard

```bash
python playsheet.py --wizard
```

Nine questions, then a finished pre-configured file. Nothing to edit afterwards.

| # | Question | What to answer |
|---|---|---|
| 1 | System name | the name in the question (EduSecure, MediSecure…) |
| 2 | Which cipher | pick from 13 — classical and modern in one list |
| 3 | Key | a sensible default is pre-filled; Enter, or type the question's key |
| 4 | Mode | only asked for DES/AES |
| 5 | Signature scheme | RSA / ECDSA / ElGamal / Schnorr |
| 6 | Hash | sha256 / sha512 / sha1 / md5 / custom |
| 7 | Sign ciphertext or plaintext | ciphertext (default) unless told otherwise |
| 8 | Roles | 5 presets (Education, Healthcare, Banking, Corporate, Legal) or custom |
| 9 | Extras | sockets, KMS, access models, attacks, DH, Rabin, ElGamal, ECC |

**Answer nothing at question 9** and you get the lean file (387 lines commented, 359 clean).
**Pick anything at question 9** and it automatically switches to the full build, because the extras live in blocks.

### Step 2 — Confirm what it wrote

The summary at the end names both files and the line count. You should see:

```
  style     : LEAN - only the cipher, hash and signature above
  size      : 387 lines
  files     : answer.py  (commented, for you)
              answer_clean.py  (no comments, to show)
```

If it says `blocks : ...` instead of `style : LEAN`, you picked an extra at question 9 and got the full build — which is correct if the question needed it.

## Skipping the questions entirely

```bash
python playsheet.py --lean AES-256 -o answer.py
python playsheet.py --lean HILL -o answer.py
```

Builds immediately with sensible defaults (RSA + SHA-256 + Student/Faculty/HoD). Change anything afterwards in the `CONFIG` block at the top.

## Forcing the full version

```bash
python playsheet.py --wizard --full
python playsheet.py --build exam -o answer.py
python playsheet.py --build lab4 -o answer.py
```

## The two files

Every route — wizard, `--lean`, `--build` — writes both:

| File | What it is |
|---|---|
| `answer.py` | every comment kept. Read it, reconfigure it, learn from it. |
| `answer_clean.py` | same program, comments and docstrings removed, three-line header. Show or submit this one. |

They are checked to behave identically before being written; if stripping ever produced something that wouldn't parse, you'd get an identical copy instead of a broken file. Run either one the same way:

```bash
python answer_clean.py demo
```

If 359 lines is still more than you want to hand in, **Trimming the clean file further** near the end lists exactly what to delete, in order, with the measured line saving and the cost of each cut. The short version: four steps take you to 252 lines with the menu intact, and that is the sensible stopping point.

## Seeing the difference

```bash
python playsheet.py --compare
```

```
lean (DES + RSA + sha256)         457
full --build exam                1236
reduction                          63%
```

## Changing your mind afterwards

```bash
python playsheet.py --reconfigure answer.py
```

Re-asks only the settings questions. On a **lean** file it regenerates the file for the new cipher and keeps your roles. On a **full** file it rewrites `CONFIG` in place and offers to add any block the new choice needs. Either way you can go from AES-256/ECDSA to Hill/ElGamal without starting over.

You can also just open the file and edit the block bracketed by:
```
# ===== SETTINGS - change these to match the question =====
# ===== END SETTINGS =====
```
(a `--build` preset file uses `# ===== EDIT THIS SECTION - CONFIG START =====` instead — same idea.)

---

# PHASE 3 — Check the configuration (1 minute)

### Step 1 — Open `answer.py` and read the `SETTINGS` block

It is a handful of plain variables at the top of the file, not a config object. If you used the wizard it is already correct — just confirm the key matches the question.

```python
# ===== SETTINGS - change these to match the question =====
system_name = "EduSecure"
key = b"A1B2C3D4"

roles = {
    "student": ["upload", "view_own"],
    "faculty": ["decrypt_verify", "view_all", "tamper_test"],
    "hod": ["view_hashes", "audit"]
}
# ===== END SETTINGS =====
```

The cipher, hash and signature scheme are not settings — they are the actual code in the file, written out plainly. To change one, rebuild with `--reconfigure`.

### How the file is laid out

Top to bottom, so you can find anything in a second:

```
imports
SETTINGS          system_name, key, roles
records, user_keys, file names
timestamp()
# ---------- Encryption and Decryption ----------
# ---------- Hashing ----------
# ---------- Digital Signature ----------
# ---------- Saving and loading ----------
# ---------- Audit log ----------
# ---------- Access Control ----------
# ---------- Upload / Verify / Tamper ----------
# ---------- Views ----------
# ---------- Menu ----------
# ---------- Full run with no typing ----------
```

No classes, no helper layer, plain `print("Label     :", value)` output.

### Step 2 — Check the key against the cheat table

| Question says | `cipher` | `key` |
|---|---|---|
| DES | `"DES"` | `"A1B2C3D4"` — exactly 8 chars |
| Triple DES | `"3DES"` | 24 chars / 48 hex |
| AES-128 | `"AES-128"` | 16 chars / 32 hex |
| AES-192 | `"AES-192"` | 24 chars / 48 hex |
| AES-256 | `"AES-256"` | 32 chars / 64 hex |
| CBC / CTR / CFB / OFB | set `"mode"` | IV handled automatically |
| Caesar / shift / additive | `"ADDITIVE"` | `20` |
| Multiplicative | `"MULTIPLICATIVE"` | `15` (must be coprime with 26) |
| Affine | `"AFFINE"` | `"15,20"` |
| Vigenère | `"VIGENERE"` | `"dollars"` |
| Autokey | `"AUTOKEY"` | `7` or `"HEALTH"` |
| Playfair | `"PLAYFAIR"` | `"GUIDANCE"` |
| Hill | `"HILL"` | `[[3,3],[2,7]]` |
| Transposition | `"TRANSPOSITION"` | `"3142"` or `"SECRET"` |

`"signature"` → `RSA` | `ECDSA` | `ELGAMAL` | `SCHNORR`
`"hash"` → `sha256` | `sha512` | `md5` | `sha1` | `custom`

A short key is zero-padded and a long one truncated, so a wrong length never crashes you — but use the question's key verbatim.

### Step 3 — Rename the roles to match the question

```python
roles = {
    "patient": ["upload", "view_own"],
    "doctor": ["decrypt_verify", "view_all", "tamper_test"],
    "admin": ["view_hashes", "audit"]
}
```

Permissions: `upload`, `view_own`, `decrypt_verify`, `view_all`, `view_hashes`, `tamper_test`, `audit`.

Give the read-only role **only** `view_hashes` — that visibly proves access control.

### Step 4 — Regenerate the clean copy if you edited by hand

`answer_clean.py` was written from the original. If you changed the `SETTINGS` block by hand, rebuild it so the two files match:

```bash
python playsheet.py --reconfigure answer.py
```

That rewrites both files and keeps them in step. It works on wizard builds and on `--build` presets alike. If you only changed one setting, editing the same line in `answer_clean.py` is quicker.

---

# PHASE 4 — Run and demonstrate (5 minutes)

### Step 1 — Prove it works before you show anyone

```bash
python answer.py demo
```

Uploads a record, verifies it, shows the read-only view, corrupts one byte and verifies again — every marking component in about four seconds. If this is clean, you are done worrying.

### Step 2 — Reset, then drive the menu live

```bash
python answer.py reset
python answer.py
```

Every built file takes the same three forms — `python <file>`, `<file> demo`, `<file> reset` — whether it came from the wizard, `--lean` or `--build`.

Demonstration order:

1. Log in as the **uploader** → upload a record (the filename from the question, e.g. `ISL-5CCE-A2.txt`, or typed text — both work) → *encryption + hashing + signing, timestamped, all in hex*
2. View own records → *stored encrypted + hashed forms*
3. Logout → log in as the **verifier** → decrypt & verify → *integrity check + signature verification + decryption*
4. Run **tamper test** → *hash mismatches, signature goes INVALID*
5. Logout → log in as the **read-only** role → *only hashes visible, no plaintext*

Step 4 is what wins marks. Most students can't show detection actually working.

### Step 3 — Hand over the clean file

Show or submit `answer_clean.py`. It is the same program without the teaching comments, and it runs identically:

```bash
python answer_clean.py demo
```

Keep `answer.py` open on your own screen — the comments are your notes for the viva.

---

# PHASE 5 — Write-up (while it runs)

### Step 1 — Copy the header

The comment block at the top of `answer.py` names the cipher, hash, signature scheme and roles for this exact build. Copy it into the record as the AIM, then add the FLOW below.

### Step 2 — Fill in the rest

```
AIM:      <System> — confidentiality via <cipher>, integrity via <hash>,
          authenticity via <signature>, with role-based access control.

FLOW:     Uploader  : plaintext -> <cipher> encrypt -> <hash> of ciphertext
                      -> sign hash with private key -> store + timestamp
          Verifier  : recompute hash and compare -> verify signature with the
                      uploader's public key -> decrypt with the shared key
                      -> store verification result + timestamp
          Read-only : sees hash + signature status only, never plaintext

ACCESS:   Each role's menu exposes only its permitted operations
          (least privilege). Unauthorised actions raise PermissionError.

STORAGE:  records.json (records), keys/keystore.json (key pairs),
          audit.log (all operations, timestamped).

RESULT:   Clean record -> integrity OK, signature VALID.
          After tampering -> integrity FAILED, signature INVALID.
```

### Step 3 — Paste the two results

Run `python answer.py demo`, then copy the two verification blocks — the clean one and the tampered one — into the record. They are the evidence that the integrity and signature checks actually fire.

All values are in hex: ciphertext, hash and signature. A classical cipher shows its letters with the hex on the line below, because the letters are the answer the question asks for.

Two things worth saying explicitly in the viva:

- **Order.** Integrity and signature are checked *before* decrypting. Never process data you have not yet proved is unmodified.
- **CBC error propagation.** After tampering one byte, only the first block of the plaintext is garbled and the rest survives. That is the chaining, and it is worth pointing at.

---

# Trimming the clean file further

`answer_clean.py` is **359 lines** for a DES or AES build (374–421 for the classical ciphers — the cipher itself is the difference). It keeps the `# ---------- Section ----------` banners and the `SETTINGS` markers; everything else explanatory is stripped.

Everything below was **tested**: each step was removed, the file re-run, and it still printed `Integrity  : OK`, `Signature  : VALID` and `FAILED - record modified` after tampering. Delete each function's section banner along with it.

Work down the list and stop whenever it is short enough.

| # | Delete | Lines | Left | Cost |
|---|---|---|---|---|
| 1 | `reset()` and its `elif` in `__main__` | −13 | 348 | delete `records.json`, `keys.json`, `audit.log` by hand between runs |
| 2 | `log_action()`, `show_log()`, every `log_action(...)` call, `log_file`, and `audit` from the roles | −18 | 330 | no audit trail — **only if the question doesn't mention logging** |
| 3 | `show_my_records()`, `show_all_records()` and their `do_action` branches | −26 | 304 | loses demonstration step 2 ("view own records") |
| 4 | `save_records()`, `load_records()`, `save_keys()`, `load_keys()` and their calls | −24 | 280 | **nothing survives a restart.** Most questions say "store the records" — think before cutting this |

Four steps, 359 → 280 lines, with both the menu and the demo still working.

Then pick one of the two endings below.

## Past that there is almost nothing left

I kept cutting to find the real floor. The next five removals together save **24 lines**, and the last one costs marks:

| Delete | Saves | Verdict |
|---|---|---|
| `show_cipher()` — inline `ciphertext.hex().upper()` | 2 | not worth it |
| `find_record()` — index the list instead | 5 | not worth it |
| `timestamp()` — inline the `strftime` call | 2 | not worth it |
| the Windows console guard | 0 | you still need `import sys` — **no saving at all** |
| `show_hashes()` | 15 | **loses the read-only role's only view** |

**225 lines is the floor.** At that point the file is almost entirely marking components:

```
 28  verify_record      hash compare -> signature check -> decrypt
 24  upload_record      encrypt -> hash -> sign -> store
 23  demo               the no-typing run for the viva
 17  tamper_record      the step most students cannot show
 13  show_hashes        the read-only role's view
  8  verify_signature   authenticity
  6  get_keys           key handling
  5  encrypt_data       confidentiality
  5  check_permission   access control
  5  find_record
  3  sign_data
  3  decrypt_data
  2  timestamp / show_cipher / hash_data
```

## Menu or demo — you do not need both

After step 4 you still have both entry points. Drop one:

| | Lines | Keeps |
|---|---|---|
| **Path B** — drop `demo()` | 252 | the full menu. You log in as each role live and access control visibly refuses. **Prefer this.** |
| **Path A** — drop `menu()` and `do_action()` | 225 | `demo()` only. Fastest to show, but `check_permission` is never called, so ACCESS DENIED never appears |

Both tested end to end. Path B costs 27 lines and keeps the access-control mark, so take Path A only if you are handing in code on paper and never running it.

## Two cuts with a cost

**Step 4 — keys and records must go together.** If you keep `save_records()` but drop `save_keys()`, a record written in one run is verified against a *different* key pair in the next, and the signature comes back INVALID for no visible reason. Remove both or neither.

**Path A — deleting the menu deletes the proof of access control.** `check_permission()` still exists, but nothing calls it, so "ACCESS DENIED" never appears on screen. Access control is worth 3 marks in the sample paper and the examiner has to *see* it refuse.

## Never remove these

They are the marking scheme:

| Keep | Why |
|---|---|
| `encrypt_data` / `decrypt_data` | confidentiality — the largest single component |
| `hash_data` | integrity |
| `sign_data` / `verify_signature` | authenticity and non-repudiation |
| `check_permission` **and a caller for it** | access control |
| `upload_record` | shows the encrypt → hash → sign order |
| `verify_record` | shows hash-compare → signature-check → decrypt |
| `tamper_record` | the step most students cannot demonstrate |
| `timestamp()` and the `"time"` field | every question asks for timestamps |
| the `SETTINGS` block | one edit re-points the whole program |

## Summary

| Version | Lines |
|---|---|
| `answer.py` as generated | 387 |
| `answer_clean.py` | 359 |
| after steps 1–4 (menu **and** demo still there) | 280 |
| Path B — menu kept, demo dropped | 252 |
| Path A — demo kept, menu dropped | 225 |

Below 225 you are deleting marks, not code.


---

# Handling every likely variation

| If the question adds… | Do this |
|---|---|
| Different cipher (any of 13) | `--reconfigure`, or change `key` and the cipher functions |
| CBC / CTR mode | `--reconfigure` — the IV is handled for you |
| ElGamal / ECDSA / Schnorr signing | `--reconfigure` |
| MD5 / SHA-512 / custom hash | `--reconfigure`, or edit the one line in `hash_data()` |
| "show all the AES steps" | `--build lab2` → `aes_show_steps(msg, key, 192)` |
| Diffie-Hellman key exchange | add `DH` → use `dh_derive_key(dh_shared(...))` as the `key` |
| Client-server / sockets | add `SOCKET` → `socket_integrity_demo()`, `socket_signature_demo()`, `socket_secure_channel_demo()`, or `write_socket_templates()` for separate `server.py` + `client.py` |
| Key revocation / renewal / logging | add `KMS` → `KeyManager("RSA")` |
| Bell-LaPadula / ABAC / DAC | add `ACCESS` |
| Performance comparison | `compare_symmetric()`, `compare_hashes()`, `compare_asymmetric()` |
| Collision detection | `collisions_truncated()` — full digests never collide, truncated ones do |
| Attack / cryptanalysis | add `ATTACK` → `affine_known_plaintext`, `brute_force_additive`, `fermat_factor`, `shared_prime_attack`, `recover_rsa_private` |
| Rabin / ElGamal / ECC encryption | add `RABIN` / `ELGAMAL` / `ECC` |
| Manual's 0x-hex RSA signature | `rsa_sign_raw`, `rsa_verify_raw`, `rsa_raw_demo()` |

---

# Manual coverage (Lab 1–6)

| Lab | Topic | Where |
|---|---|---|
| 1 | additive, multiplicative, affine | `CLASSIC_SUB` |
| 1 | Vigenère, autokey | `CLASSIC_POLY` |
| 1 | Playfair | `CLASSIC_PLAYFAIR` |
| 1 | Hill (any n×n) | `CLASSIC_HILL` |
| 1 | columnar + rail-fence transposition | `CLASSIC_TRANS` |
| 1 | brute force, known-plaintext, permutation key size | `ATTACK` |
| 2 | DES, 3DES, AES-128/192/256 | `SYM` |
| 2 | ECB, CBC, CFB, OFB, CTR | `SYM` |
| 2 | timing comparison | `compare_symmetric()` |
| 2 | AES key expansion + round structure | `AESSTEPS` |
| 3 | RSA textbook + 2048-bit + hybrid | `RSA` |
| 3 | ECC / ECIES | `ECC` |
| 3 | ElGamal | `ELGAMAL` |
| 3 | Diffie-Hellman | `DH` |
| 3 | RSA vs ECC performance | `PERF` |
| 4 | Rabin | `RABIN` |
| 4 | key generate/distribute/revoke/renew/store/log | `KMS` |
| 4 | RBAC, ABAC, Bell-LaPadula, MAC, DAC, time-based | `ACCESS` |
| 4 | weak RSA: trial division, Fermat close primes, shared prime | `ATTACK` |
| 5 | custom djb2 hash (5381 / ×33 / 32-bit mask) | `HASH` |
| 5 | MD5 / SHA-1 / SHA-256 timing | `compare_hashes()` |
| 5 | collision detection | `collisions_truncated()` |
| 5 | socket integrity + multi-part reassembly | `SOCKET` |
| 6 | RSA / ECDSA / ElGamal / Schnorr signatures | `SIGN` |
| 6 | raw RSA in the manual's 0x-hex format | `rsa_raw_demo()` |
| 6 | client-server verification | `SOCKET` |
| 6 | CIA triad | `secure_send()` / `secure_receive()` |

Per-lab builds: `--build lab1` … `--build lab6`.

---

# Viva answers

- **Why sign the ciphertext, not the plaintext?** So a read-only role can verify authenticity without decryption rights. In the generated file the hash and signature are taken over the ciphertext; to sign the plaintext instead, pass `message.encode()` to `hash_data` and `sign_data` in `upload_record`.
- **Why check integrity before decrypting?** You should never process data you haven't proved is unmodified.
- **Why does the classical version drop spaces and digits?** Classical ciphers operate on the 26-letter alphabet only — inherent to the cipher, not the implementation. Block ciphers preserve arbitrary bytes.
- **Why is ECB weak?** Identical plaintext blocks give identical ciphertext blocks, so patterns leak. CBC/CTR with a fresh IV fixes it.
- **Why hybrid encryption?** RSA encrypts only ~190 bytes at 2048 bits and is slow; AES handles bulk data, RSA protects only the session key.
- **Why isn't a hash alone enough?** An attacker can alter the data *and* recompute the hash. A signature or HMAC binds it to a key.
- **Hill decryption?** Needs the key matrix inverse mod 26 — the determinant must be coprime with 26.
- **Rabin vs RSA?** Rabin encryption is one squaring and its security provably equals factoring, but decryption yields four roots, so redundancy is needed to pick the right one.
- **DES weakness?** 56-bit key is brute-forceable today; use AES or 3DES.
- **Why does Fermat break RSA with close primes?** n = a²−b² = (a−b)(a+b); starting at ⌈√n⌉ finds it in a handful of steps when p and q are adjacent.
- **Why did the collision count show 0?** Full 256-bit digests never collide on a small dataset. Truncate to 16–24 bits and the birthday bound (~2^(n/2)) shows up immediately.
- **Why must k be fresh in ElGamal/Schnorr/DSA?** Reusing it gives two equations in the same unknown — the private key falls out.

---

# Command reference

```bash
python playsheet.py                           # help, then offers the wizard
python playsheet.py --venv                    # venv + install instructions
python playsheet.py --setup                   # pip install everything
python playsheet.py --check                   # environment check
python playsheet.py --selftest                # 153 checks
python playsheet.py --wizard                  # BUILDER (lean, the default)
python playsheet.py --wizard --full           # BUILDER (every block)
python playsheet.py --lean AES-256 -o answer.py    # no questions
python playsheet.py --reconfigure answer.py   # change an existing answer file
python playsheet.py --compare                 # lean vs full size
python playsheet.py --blocks                  # list blocks + presets
python playsheet.py --build exam -o answer.py
python playsheet.py --demo                    # modern + classical demo
```

Every build writes `answer.py` **and** `answer_clean.py`. Run either:

```bash
python answer.py demo          # commented version
python answer_clean.py demo    # stripped version, identical output
python answer.py reset         # clear records / keys / log
```

**Presets:** `exam` · `classical` · `network` · `keymgmt` · `lab1`–`lab6` · `all`

**Blocks:** CORE · CLASSIC_SUB · CLASSIC_POLY · CLASSIC_PLAYFAIR · CLASSIC_HILL · CLASSIC_TRANS · SYM · AESSTEPS · RSA · PERF · ELGAMAL · RABIN · DH · ECC · HASH · SIGN · KMS · ACCESS · SOCKET · ATTACK · DISPATCH · TEMPLATE

---

# If something breaks mid-exam

| Problem | Fix |
|---|---|
| `ModuleNotFoundError: Crypto` | `pip install pycryptodome` (not `pycrypto`), and check `(.venv)` is in your prompt |
| Installed it but still missing | wrong interpreter — `python playsheet.py --check` prints which one is running |
| PowerShell won't activate the venv | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` |
| pip: "externally managed environment" | add `--break-system-packages` |
| `Triple DES key degenerates` | already handled — the code re-derives a valid key |
| `Hill key not invertible` | determinant must be coprime with 26; `[[3,3],[2,7]]` works |
| Classical cipher loses spaces | expected — say so in the write-up |
| Port already in use | demos bind a free port automatically; for `server.py` change `PORT` |
| Stale records from testing | `python answer.py reset` |
| Examiner wants code without comments | already there — `answer_clean.py` |
| Answer file still feels too long | see **Trimming the clean file further** — 359 → 225 lines, all tested |
| Need a value in hex | `hexs(x)` handles bytes, ints and text; `hexs(x, 2)` groups it in byte pairs |
| Wrong cipher chosen | `python playsheet.py --reconfigure answer.py` |
| Answer file feels too big | you built `--full`; rebuild with `--wizard` and skip question 9 |
| `SyntaxWarning: invalid escape sequence` | fixed — harmless anyway, it never stopped the program |
| `PermissionError: Access is denied` on reset | fixed — teardown is best-effort now. It was OneDrive holding the folder |
| `UnicodeEncodeError: 'charmap' codec` | fixed — output is forced ASCII-safe. If you see it in your own added code, wrap the value in `safe_text(...)` |
| Tampered plaintext shows dots | correct — those are unprintable bytes. Only the first block is garbled in CBC; that is error propagation, worth saying in the viva |
| Everything on fire | `python playsheet.py --lean DES -o answer.py` — one command, working file |
