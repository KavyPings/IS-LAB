# Manual-vs-wizard audit (all three manuals, exercises + additional)

## Already covered
AES-128/192/256, DES, 3DES; ECB/CBC/CFB/OFB/CTR; RSA and ECC key wrapping;
SHA-512/256/1 and MD5; RSA/DSA/ECDSA/ElGamal/Schnorr signatures; Paillier,
RSA-multiplicative and ElGamal-multiplicative homomorphism; SSE and PKSE;
Shamir threshold; trusted timestamps and deadlines; TCP client/server; RBAC;
audit logging; tamper tests.

## Gaps found in the manuals

| manual | method | where it is asked for |
| --- | --- | --- |
| Lab 3 Q3, Lab 4 Q1/DRM | **ElGamal encryption** (not just signing/HE) | "encrypt the message with public key (p,g,h)" |
| Lab 4 Q2 | **Rabin cryptosystem** | HealthCare Inc. patient records, 1024-bit, "trade-off vs RSA" |
| Lab 3 Q5, Lab 4 Q1, Lab 6 Q2 | **Diffie-Hellman key exchange** | peer-to-peer shared secret; "RSA + DH" |
| Lab 5 Q1 | **custom djb2 hash** (5381, x33, 32-bit mask) | "implement the hash function in Python" |
| Lab 2 additional 1a | **more modes of operation** | "consider different modes" - AEAD is the modern answer |
| Lab 4 | **ABAC** attribute-based access control | listed with its policy function |
| Lab 4 | **Bell-LaPadula** no-read-up / no-write-down | listed with both properties |
| Lab 4 | **MAC** clearance vs classification | listed |
| Lab 4 | **DAC** access matrix | listed |
| Lab 4 | **time-based access control** | listed; DRM "limited-time access" |
| Lab 4 | **probabilistic access control** | listed with the trust/sensitivity/risk function |
| Lab 4 Q1/Q2, DRM | **key management**: generate, distribute, revoke, renew, rotate, expiry | two whole questions |
| Lab 4 | **secure key storage** + KDF(key, salt, iterations) | "not accessible to unauthorized parties" |
| Lab 2 Q3, Lab 3 Q4/Q5, Lab 7 1d | **performance comparison** | "measure and compare ... report findings" |
| Lab 5 additional | **multipart socket transfer** then reassemble and hash | separate exercise |

## Not in the manual, worth adding anyway
HMAC keyed integrity tag; hash-chained (tamper-evident) audit log; replay
protection via a seen-nonce set plus a timestamp window; AES-GCM / EAX
authenticated encryption.

## Deliberately not added
Snort and GnuPG (Lab 8 additional) are external tools, already answered as
standalone files in Lab8_Searchable_Encryption/additional_questions/.
Classical ciphers stay in the mid-sem wizard, where the syllabus puts them.
