# playsheet.py — the mid-sem answer writer (Labs 1–6)

Kept as it was for the mid-sem exam. The full strategy, the measured
trimming staircase and the viva answers are in `MIDSEM_EXAM_PLAN.md` in this
folder; this file is just the command list.

From the IS Lab folder, every command here is also reachable as
`python wizard.py --midsem <flag>`, which saves typing the path.

## Setup

```
cd "C:\Users\kavyk\OneDrive\Desktop\Projects\IS Lab"
python -m venv .venv
.venv\Scripts\activate              # Windows
source .venv/bin/activate           # macOS / Linux
pip install pycryptodome
python playsheet.py --check
python playsheet.py --selftest      # 153 checks, should all pass
```

## Use

```
python playsheet.py --wizard        answer the questions -> answer.py
python playsheet.py --wizard --full the larger build with every helper
python playsheet.py --lean AES-256  the smallest single-cipher answer
python playsheet.py --blocks        list the code blocks it can emit
python playsheet.py --compare       size comparison of the build options
python playsheet.py --demo          run the default build immediately
python playsheet.py --reconfigure   change the SETTINGS of an existing answer
```

It writes `answer.py` (with comments) and `answer_clean.py` (comments
stripped, section banners kept).

## What it covers

Labs 1–6: classical ciphers, DES / 3DES / AES in five modes, AES key
expansion, RSA (library and textbook), ElGamal, ECC / ECIES, Rabin,
Diffie-Hellman, SHA-1/256/512, MD5, a custom hash, HMAC, RSA / DSA / ECDSA /
ElGamal / Schnorr signatures, a key management service, RBAC and DAC access
control, length-framed sockets, and the brute-force / known-plaintext /
Fermat / shared-prime attacks.

## What it does NOT cover

Lab 7 (partial homomorphic encryption) and Lab 8 (searchable encryption),
threshold decryption and trusted timestamps. For any question mentioning
those, use `../Endsem_Wizard/endsheet.py` instead.
