"""
LAB 1 - SAMPLE / SCENARIO QUESTION (exam style practice)

"SecureNotes is a small classified-notes application used by a research team.
 Notes must be stored using classical ciphers chosen by the user. Build a
 menu-driven Python program that lets the user
    1. encrypt a note with a cipher of their choice
       (additive / multiplicative / affine / Vigenere / Playfair / Hill),
    2. decrypt a stored note,
    3. list all stored notes with their cipher and timestamp,
    4. attempt to break an additive or affine note by brute force."

This is the Lab-1 version of the mid-term pattern:
   menu  +  choice of algorithm  +  stored records with timestamps.
Reuse the structure; only the cipher functions change per question.
"""

import json
import os
from datetime import datetime

# every cipher lives in the Concepts file - here they are inlined so this
# script runs on its own
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "..", "Concepts"))

DB = "securenotes.json"


def clean(t):
    return "".join(c for c in t.upper() if c.isalpha())


def mod_inverse(a, m=26):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None


# --- ciphers ---------------------------------------------------------------
def additive(t, k, enc=True):
    s = 1 if enc else -1
    return "".join(chr((ord(c) - 65 + s * k) % 26 + 65) for c in clean(t))


def multiplicative(t, k, enc=True):
    kk = k if enc else mod_inverse(k)
    return "".join(chr(((ord(c) - 65) * kk) % 26 + 65) for c in clean(t))


def affine(t, a, b, enc=True):
    if enc:
        return "".join(chr(((ord(c) - 65) * a + b) % 26 + 65) for c in clean(t))
    ai = mod_inverse(a)
    return "".join(chr((ai * (ord(c) - 65 - b)) % 26 + 65) for c in clean(t))


def vigenere(t, kw, enc=True):
    t, k = clean(t), clean(kw)
    s = 1 if enc else -1
    return "".join(chr(((ord(t[i]) - 65) + s * (ord(k[i % len(k)]) - 65)) % 26 + 65)
                   for i in range(len(t)))


# --- storage ---------------------------------------------------------------
def load():
    return json.load(open(DB)) if os.path.exists(DB) else []


def save(notes):
    json.dump(notes, open(DB, "w"), indent=2)


def store_note(cipher_name, key, ciphertext):
    notes = load()
    notes.append({"id": len(notes) + 1, "cipher": cipher_name, "key": str(key),
                  "ciphertext": ciphertext,
                  "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
    save(notes)
    return notes[-1]


# --- attacks ---------------------------------------------------------------
def brute_additive(ct):
    return [(k, additive(ct, k, False)) for k in range(26)]


def brute_affine(ct, contains="THE"):
    out = []
    for a in range(1, 26):
        if mod_inverse(a) is None:
            continue
        for b in range(26):
            pt = affine(ct, a, b, False)
            if contains in pt:
                out.append((a, b, pt))
    return out


# --- menu ------------------------------------------------------------------
def encrypt_menu():
    print("  1 additive  2 multiplicative  3 affine  4 vigenere")
    c = input("  cipher> ").strip()
    note = input("  note text: ")
    if c == "1":
        k = int(input("  key (0-25): ")); ct = additive(note, k); name, key = "additive", k
    elif c == "2":
        k = int(input("  key (coprime with 26): ")); ct = multiplicative(note, k); name, key = "multiplicative", k
    elif c == "3":
        a = int(input("  a: ")); b = int(input("  b: ")); ct = affine(note, a, b); name, key = "affine", (a, b)
    elif c == "4":
        kw = input("  keyword: "); ct = vigenere(note, kw); name, key = "vigenere", kw
    else:
        print("  ! bad choice"); return
    rec = store_note(name, key, ct)
    print(f"  stored #{rec['id']}  cipher={ct}  at {rec['timestamp']}")


def decrypt_menu():
    notes = load()
    if not notes:
        print("  (nothing stored)"); return
    i = int(input("  note id: "))
    n = next((x for x in notes if x["id"] == i), None)
    if not n:
        print("  ! no such note"); return
    ct, name, key = n["ciphertext"], n["cipher"], n["key"]
    if name == "additive":
        pt = additive(ct, int(key), False)
    elif name == "multiplicative":
        pt = multiplicative(ct, int(key), False)
    elif name == "affine":
        a, b = eval(key); pt = affine(ct, a, b, False)
    else:
        pt = vigenere(ct, key, False)
    print(f"  cipher={name} key={key}")
    print(f"  plaintext: {pt}")


def main():
    while True:
        print("\n=== SecureNotes ===")
        print("1 encrypt   2 decrypt   3 list   4 brute force   0 exit")
        c = input("choice> ").strip()
        if c == "1":
            encrypt_menu()
        elif c == "2":
            decrypt_menu()
        elif c == "3":
            for n in load():
                print(f"  #{n['id']:<3}{n['cipher']:<16}{n['timestamp']:<21}{n['ciphertext']}")
        elif c == "4":
            ct = input("  ciphertext: ").upper()
            print("  additive candidates:")
            for k, pt in brute_additive(ct):
                print(f"     k={k:2d} {pt}")
            print("  affine candidates containing 'THE':")
            for a, b, pt in brute_affine(ct):
                print(f"     a={a} b={b} {pt}")
        elif c == "0":
            return


if __name__ == "__main__":
    main()
