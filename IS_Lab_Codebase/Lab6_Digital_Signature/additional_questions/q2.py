"""
LAB 6 - ADDITIONAL 2 (based on the manual's Part 1)
Working with raw RSA signatures the way the online tool in the manual does.

WHAT THE MANUAL'S TOOL ACTUALLY DOES
  sign   : take the text as a big number m, output s = m^d mod n
  verify : take the signature s, output m = s^e mod n  and show it as text
  That is why "Alice" appears in the Text box after clicking Verify - the
  tool is just applying the public exponent and printing the bytes.

This script reproduces that with the keys printed in the manual, and also
shows the modern, correct way (hash-then-sign with PKCS#1 v1.5).
"""

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# --- the manual's Table 1 keys --------------------------------------------
PUBLIC_MODULUS_HEX = (
    "d94d889e88853dd89769a18015a0a2e6bf82bf356fe14f251fb4f5e2df0d9f9a94a"
    "68a30c428b39e3362fb3779a497eceaea37100f264d7fb9fb1a97fbf621133de55f"
    "dcb9b1ad0d7a31b379216d79252f5c527b9bc63d83d4ecf4d1d45cbf843e8474ba"
    "bc655e9bb6799cba77a47eafa838296474afc24beb9c825b73ebf549")
PRIVATE_EXPONENT_HEX = (
    "47b9cfde843176b88741d68cf096952e950813151058ce46f2b048791a26e507a"
    "1095793c12bae1e09d82213ad9326928cf7c2350acb19c98f19d32d577d666cd7"
    "bb8b2b5ba629d25ccf72a5ceb8a8da038906c84dcdb1fe677dffb2c029fd892631"
    "8eede1b58272af22bda5c5232be066839398e42f5352df58848adad11a1")
PUBLIC_EXPONENT = 0x10001                       # 65537, the manual's "10001"

BOB_SIG = """
0x6c 0x99 0xd6 0xa8 0x42 0x53 0xee 0xb5 0x2d 0x7f 0x0b 0x27 0x17 0xf1 0x1b 0x62
0x92 0x7f 0x92 0x6d 0x42 0xbd 0xc6 0xd5 0x3e 0x5c 0xe9 0xb5 0xd2 0x96 0xad 0x22
0x5d 0x18 0x64 0xf3 0x89 0x52 0x08 0x62 0xe2 0xa2 0x91 0x47 0x94 0xe8 0x75 0xce
0x02 0xf8 0xe9 0xf8 0x49 0x72 0x20 0x12 0xe2 0xac 0x99 0x25 0x9a 0x27 0xe0 0x99
0x38 0x54 0x54 0x93 0x06 0x97 0x71 0x69 0xb1 0xb6 0x24 0xed 0x1c 0x89 0x62 0x3d
0xd2 0xdf 0xda 0x7a 0x0b 0xd3 0x36 0x37 0xa3 0xcb 0x32 0xbb 0x1d 0x5e 0x13 0xbc
0xca 0x78 0x3e 0xe6 0xfc 0x5a 0x81 0x66 0x4e 0xa0 0x66 0xce 0xb3 0x1b 0x93 0x32
0x2c 0x91 0x4c 0x58 0xbf 0xff 0xd8 0x97 0x2f 0xa8 0x57 0xd7 0x49 0x93 0xb1 0x62
"""

ALICE_SIG = """
0xc8 0x93 0xa9 0x0d 0x8f 0x4e 0xc5 0xc3 0x64 0xec 0x86 0x9d 0x2b 0x2e 0xc9 0x21
0xe3 0x8b 0xab 0x23 0x4a 0x4f 0x45 0xe8 0x96 0x9b 0x98 0xbe 0x25 0x41 0x15 0x9e
0xab 0x6a 0xfb 0x75 0x9a 0x13 0xb6 0x26 0x04 0xc0 0x60 0x72 0x28 0x1a 0x73 0x45
0x71 0x83 0x42 0xd4 0x7f 0x57 0xd1 0xac 0x91 0x8c 0xae 0x2f 0x3b 0xd2 0x99 0x30
0x3e 0xe8 0xa8 0x3a 0xb3 0x5d 0xfb 0x4a 0xc9 0x18 0x19 0xfd 0x3f 0x0c 0x0a 0x1f
0x3d 0xa4 0xa4 0xfe 0x02 0x9d 0x96 0x2f 0x50 0x34 0xd3 0x95 0x55 0xe0 0xb7 0x2a
0x46 0xa4 0x9e 0xae 0x80 0xc9 0x77 0x43 0x16 0xc0 0xab 0xfd 0xdc 0x88 0x95 0x05
0x56 0xdf 0xc4 0xfc 0x13 0xa6 0x48 0xa3 0x3c 0xe2 0x87 0x52 0xc5 0x3f 0x0c 0x0d
"""


# --------------------------------------------------------------- helpers
def parse_spaced_hex(text):
    """'0xc8 0x93 ...' -> bytes"""
    return bytes(int(t, 16) for t in text.split())


def hex_spaced(b):
    """bytes -> '0xc8 0x93 ...' (the manual's display format)"""
    return " ".join(f"0x{x:02x}" for x in b)


def raw_sign(text, n, d):
    """s = m^d mod n, with the text interpreted directly as a number."""
    m = int.from_bytes(text.encode(), "big")
    return pow(m, d, n)


def raw_verify(signature_int, n, e):
    """m = s^e mod n; return the number and its bytes."""
    m = pow(signature_int, e, n)
    return m, m.to_bytes((m.bit_length() + 7) // 8 or 1, "big")


if __name__ == "__main__":
    n = int(PUBLIC_MODULUS_HEX, 16)
    d = int(PRIVATE_EXPONENT_HEX, 16)
    e = PUBLIC_EXPONENT

    print("=== the manual's key material ===")
    print(f"  modulus n        : {n.bit_length()} bits")
    print(f"  public exponent e: {e} (0x{e:x})")
    print(f"  private exponent : {d.bit_length()} bits")

    print("\n=== Step 1/3 : sign your own name (raw RSA, like the tool) ===")
    name = "Kavy Khilrani"
    sig = raw_sign(name, n, d)
    sig_bytes = sig.to_bytes((n.bit_length() + 7) // 8, "big")
    print(f"  text      : {name}")
    print(f"  signature : {hex_spaced(sig_bytes)[:95]} ...")

    print("\n=== Step 2/4 : verify it (apply the PUBLIC exponent) ===")
    m, raw = raw_verify(sig, n, e)
    print(f"  recovered bytes : {raw}")
    print(f"  as text         : {raw.decode(errors='replace')}")
    print("  -> the name comes back, exactly like the website's Verify button")

    print("\n=== verifying the manual's stored signatures (Table 2 and 4) ===")
    for who, blob in (("Alice", ALICE_SIG), ("BOB", BOB_SIG)):
        sig_bytes = parse_spaced_hex(blob)
        m2, raw2 = raw_verify(int.from_bytes(sig_bytes, "big"), n, e)
        print(f"  {who:<6}: {len(sig_bytes)} byte signature -> "
              f"s^e mod n = {raw2!r}")
    print("  -> exactly the answer the manual expects: the name appears.")

    print("\n" + "=" * 68)
    print("THE CORRECT MODERN WAY - hash then sign, with padding")
    print("=" * 68)
    key = RSA.generate(2048)
    doc = "Legal document signed by Alice"
    signature = pkcs1_15.new(key).sign(SHA256.new(doc.encode()))
    print("  document  :", doc)
    print("  SHA-256   :", SHA256.new(doc.encode()).hexdigest())
    print("  signature :", hex_spaced(signature)[:95], "...")

    def verify(text, sig, pub):
        try:
            pkcs1_15.new(pub).verify(SHA256.new(text.encode()), sig)
            return True
        except (ValueError, TypeError):
            return False

    print("  verify    :", verify(doc, signature, key.publickey()))
    print("  tampered  :", verify(doc + ".", signature, key.publickey()))

    print("""
WHY RAW RSA IS NOT USED IN PRACTICE
  * the message must be shorter than the modulus
  * it is MALLEABLE: sig(a) * sig(b) mod n = sig(a*b), so signatures can be
    combined to forge new ones
  * an attacker can pick any s and compute m = s^e mod n - a valid
    "signature" on meaningless but sometimes useful data
  Hashing first (SHA-256) and adding PKCS#1 v1.5 or PSS padding removes all
  three problems, and lets you sign a document of any length.""")
