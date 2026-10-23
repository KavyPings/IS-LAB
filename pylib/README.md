# pylib — the pure-Python crypto fallback

You only need this folder if your machine refuses to load pycryptodome's
compiled modules:

```
OSError: Cannot load native module 'Crypto.Hash._SHA1':
         Not found '_SHA1.cp312-win_amd64.pyd',
         Cannot load '_SHA1.pyd': [WinError 4551]
         An Application Control policy has blocked this file
```

`4551` and `0x11c7` are the same error. It is **not** a missing package —
Windows Defender Application Control (WDAC) or Smart App Control is refusing
an unsigned binary, so reinstalling, changing folders or making a new venv
cannot fix it.

## What this does

Most of pycryptodome is ordinary Python: the RSA key class, the ASN.1 and PEM
code, PKCS#1 padding and signatures, the prime generation in
`Crypto.Util.number`. Only the ciphers, hashes and a few helpers are native.
So this folder supplies pure-Python versions of exactly those, registers them
under their normal `Crypto.*` names, and lets the real library run on top.

| file | what is in it |
| --- | --- |
| `islab_compat.py` | the installer: probes pycryptodome, and on failure registers everything below |
| `_pure_aes.py` | AES-128/192/256 (FIPS-197). The S-box is computed from the field inverse, not typed in |
| `_pure_des.py` | DES and Triple DES (FIPS 46-3), with the degenerate-key check |
| `_pure_modes.py` | ECB, CBC, CFB, OFB, CTR, GCM, EAX, and CMAC/OMAC1 |
| `_pure_hash.py` | `Crypto.Hash.*` backed by Python's own `hashlib`, plus HMAC, CMAC, SHAKE, `strxor`, `_cpu_features` |
| `_pure_oaep.py` | PKCS#1 OAEP (RFC 8017), because pycryptodome's uses a native decoder |
| `_pure_ecc.py` | NIST P-256 / P-384 / P-521, ECDSA, and DSA signing — `Crypto.PublicKey.ECC` and `Crypto.Signature.DSS` |
| `sitecustomize.py` | auto-loads the fallback when this folder is on `PYTHONPATH` |

Kept real: `Crypto.PublicKey.RSA`, `Crypto.PublicKey.DSA`,
`Crypto.Signature.pkcs1_15`, `Crypto.Signature.pss`, `Crypto.Protocol.KDF`,
`Crypto.IO.PEM`, `Crypto.Util.asn1`, `Crypto.Util.number`,
`Crypto.Util.Padding`, `Crypto.Random`.

## How to use it

Three ways, in order of convenience:

1. **Nothing to do.** `python wizard.py` loads it automatically, and an answer
   file built on a blocked machine gets one `import islab` line at the top.
2. **`import islab`** as the first line of any file you write yourself, when
   that file sits in the IS Lab folder.
3. **Once per machine**, so the per-lab question files work from their own
   folders with no edits at all:

   ```
   setx PYTHONPATH "C:\Users\kavyk\OneDrive\Desktop\Projects\IS Lab\pylib"
   ```

   Open a new terminal afterwards. `sitecustomize.py` then loads for every
   Python process. On macOS / Linux: `export PYTHONPATH=".../IS Lab/pylib"`.

Check which backend is in use at any time:

```
python islab.py
python wizard.py --check
```

## Is it correct?

Verified against the real pycryptodome, both directions:

* AES matches the FIPS-197 known-answer vectors for 128, 192 and 256-bit keys.
* DES matches the standard worked example
  (`133457799BBCDFF1` / `0123456789ABCDEF` → `85E813540F0AB405`).
* CMAC matches the RFC 4493 test vectors.
* Every mode — ECB, CBC, CFB-8, CFB-128, OFB, CTR, GCM, EAX, with and without
  associated data — produces **byte-identical** ciphertext and tags to
  pycryptodome for the same key, IV and nonce.
* Keys, PEM files, signatures and ciphertexts cross over in both directions: a
  key or signature made with the real library verifies here, and one made here
  verifies with the real library. So anything produced on a lab machine still
  opens at home.
* The whole codebase passes in both modes: all 22 runnable files, and all 40
  wizard configurations built and run.

## What it does not provide

`scrypt` and nothing else. No file in this codebase uses it; calling it raises
a clear `NotImplementedError` rather than failing quietly.

## In the viva

If asked why that `import islab` line is there: *"the lab machine's
Application Control policy blocks pycryptodome's compiled modules, so the
ciphers and hashes are pure-Python replacements registered under the same
names — the cryptography in the answer is unchanged, and the output is
byte-identical."*
