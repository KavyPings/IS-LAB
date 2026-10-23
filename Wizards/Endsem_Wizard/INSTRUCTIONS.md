# endsheet.py — the end-sem answer writer (Labs 1–8)

All commands below are shown as `python endsheet.py ...`, which works when
you are standing in this folder. From the IS Lab folder — which is where you
normally are — use the launcher instead and the flags are identical:

```
python wizard.py --check            ==  python Wizards\Endsem_Wizard\endsheet.py --check
python wizard.py --build evoting    ==  python Wizards\Endsem_Wizard\endsheet.py --build evoting
python wizard.py                    ==  python Wizards\Endsem_Wizard\endsheet.py --wizard
```

## 0. Before the exam, once

```
cd "C:\Users\kavyk\OneDrive\Desktop\Projects\IS Lab"
python -m venv .venv
.venv\Scripts\activate              # Windows
source .venv/bin/activate           # macOS / Linux
pip install pycryptodome
python endsheet.py --check
```

`--check` must print `ENVIRONMENT READY`. Nothing else is installed, and
nothing here needs the network.

Then prove it works end to end while there is no time pressure:

```
python endsheet.py --build evoting
python answer.py demo
python answer.py                    # click through every menu item once
python answer.py reset
```

Optionally, `python endsheet.py --selftest` builds and runs 40 different
configurations (about four minutes). It should print `40/40 passed`.

## 1. In the exam, read the question with this list beside you

| Read the question for | It sets |
| --- | --- |
| "AES-256 in CBC mode", "DES", "3DES" | cipher and mode |
| "encrypt the key with the RSA public key" | key wrap = RSA |
| "SHA-512", "SHA-256", "MD5" | hash |
| "ElGamal / RSA / DSA / ECDSA / Schnorr signature" | signature scheme |
| "tally / total / aggregate without decrypting" | homomorphic = PAILLIER |
| "product of encrypted values" | homomorphic = ELGAMAL_MUL or RSA_MUL |
| "searchable index", "search by X without revealing" | search = SSE (or PKSE if it says public key) |
| "no single authority can decrypt" | threshold = yes |
| "trusted timestamp", "before the deadline" | timestamps = yes |
| "client side … server side" | sockets = yes |
| the role names (voter / officer / auditor …) | roles |

## 2. Build it

```
python endsheet.py --wizard
```

Press Enter to accept every `[default]`. The first question picks the closest
ready-made scenario, and the rest only adjust it:

```
evoting     end-sem sample paper: secure electronic voting system
trade       financial trade reports, RSA signatures, encrypted totals
medical     hospital records, ECDSA, encrypted comparison of readings
banking     bank transactions, DSA signatures, multiplicative RSA
documents   Lab 8 shaped question: encrypted document store with search
minimal     smallest answer that still earns ED + DSS + Hash marks
custom      start from the defaults and set everything
```

Non-interactive equivalent, if you already know what you want:

```
python endsheet.py --build evoting
```

`python endsheet.py --options` lists every value each setting accepts.

## 3. Run it

```
python answer.py demo      full run, no typing, prints every output
python answer.py           the interactive menu  <- what gets marked
python answer.py netdemo   a real TCP client and server in one process
python answer.py server    terminal 1
python answer.py client    terminal 2
python answer.py reset     delete the stored files, start clean
```

Run `demo` first. It exercises every component in order, so if something is
wrong you see it before the examiner does. Then run the menu and click
through it, because the sample paper says a program that is not menu-driven
scores half marks.

## 4. The five marked components, and where they are in the output

| Component | What to point at |
| --- | --- |
| Client-Server | `submit_record` on the client, `verify_record` on the server, and the `netdemo` TCP exchange |
| ED | the IV, the cipher ciphertext and the wrapped session key lines |
| DSS | `Output: <scheme> signature valid`, and `INVALID` after the tamper test |
| Hash | the digest line, and `recomputed <hash> DOES NOT MATCH` after tampering |
| Search | `search_by_tag` and `search_by_time_range`, with the note that the server matched tokens only |

## 5. Editing the answer instead of rebuilding it

The top of `answer.py` looks like this:

```python
# ===== SETTINGS - change these to match the question =====
system_name = "SecureVote"
record_word = "ballot"
roles = { ... }
key_bytes = 32
rsa_bits = 2048
...
# ===== END SETTINGS =====
```

Everything the examiner is likely to change mid-question is in that block.
Change it there; nothing below needs touching. In particular:

* `rsa_bits = 4096` if the question insists. The key is cached in
  `server_private.pem`, so only the first run is slow.
* set `window_closes` to a past time to demonstrate a rejected late
  submission.
* add or rename a role, and the menus follow automatically on the next build.

## 6. What to delete if the answer must be shorter

In `answer_clean.py`, in this order, each step independently safe:

1. the `# ---------- Client-Server over TCP ----------` section and the
   `netdemo` / `server` / `client` branches at the bottom — only if the
   question has no client-server component.
2. `one_share_alone()` and its menu entry — it is a demonstration, not a
   requirement.
3. `show_hashes`, `view_own`, `view_all` — keep at least one, the auditor
   role needs something to do.
4. the `demo()` function — but keep it until after the examiner has seen it,
   it is the fastest way to show every output.

Do **not** delete: `check_permission` (that is the access-control mark),
`log_action` (the audit trail), or any of the five components above.

## 7. If something breaks mid-exam

* `ModuleNotFoundError: Crypto` — the virtual environment is not active.
  Activate it, or `pip install pycryptodome`.
* `PermissionError` on reset (Windows) — close the file, or just use a new
  record id instead of resetting.
* RSA-4096 keygen is taking too long — set `rsa_bits = 2048`, say in the
  write-up that 4096 only changes the key size.
* the wizard refuses to build — `python wizard.py --build minimal` always
  works, then add what the question needs from
  `IS_Lab_Codebase/Concepts/ALL_CONCEPTS_TOOLKIT.py`.
* `can't open file '...endsheet.py'` — you are in the wrong folder. `cd` into
  the IS Lab folder and use `python wizard.py`.
* `OSError: Cannot load native module ... error 0x11c7` — an Application
  Control policy is blocking pycryptodome's compiled files. `python
  wizard.py` loads the pure-Python fallback in `pylib/` automatically, and
  the answer it writes carries one `import islab` line so it runs on its own.
  See `pylib/README.md`.
* anything else — the generated file is plain Python with no imports beyond
  pycryptodome. Read the traceback, it will point at one function.
