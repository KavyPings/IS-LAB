"""
LAB 5 - EXERCISE 1
Implement a hash function in Python:
  * start with an initial hash value of 5381
  * for each character: multiply the current hash by 33, add the ASCII value
  * use bitwise operations to mix the bits thoroughly
  * mask the result to stay inside 32 bits

This is the well-known djb2 hash with extra mixing.

WHY EACH STEP EXISTS
  5381 and 33   : empirically chosen constants that spread values well
  hash * 33     : shifts old bits upward so earlier characters keep influence
  + ord(ch)     : brings the new character in
  XOR with a shift : mixes HIGH bits back into the LOW bits (avalanche)
  & 0xFFFFFFFF  : keeps the value in 32 bits (python ints are unbounded)
"""


def custom_hash(text):
    h = 5381                                   # initial value
    for ch in text:
        h = (h * 33) + ord(ch)                 # multiply by 33, add ASCII
        h ^= (h >> 15)                         # mix high bits into low bits
        h = (h << 5) ^ h                       # extra diffusion
        h &= 0xFFFFFFFF                        # stay within 32 bits
    return h & 0xFFFFFFFF


def custom_hash_trace(text):
    """Same function, printing every step - use this for the write-up."""
    h = 5381
    print(f"  initial            = {h} (0x{h:08X})")
    for ch in text:
        h = (h * 33 + ord(ch)) & 0xFFFFFFFF
        h ^= (h >> 15)
        h = ((h << 5) ^ h) & 0xFFFFFFFF
        print(f"  after '{ch}' (ord {ord(ch):3d}) = {h:10d} (0x{h:08X})")
    return h


def hamming(a, b):
    """Number of differing bits between two 32-bit values."""
    return bin(a ^ b).count("1")


if __name__ == "__main__":
    for s in ("hello", "Hello", "hellp", "information security", ""):
        print(f"{s!r:<24} -> {custom_hash(s):10d}  0x{custom_hash(s):08X}")

    print("\nstep-by-step trace for 'Hash':")
    custom_hash_trace("Hash")

    print("\nAVALANCHE TEST (1 character changed):")
    a, b = custom_hash("hello"), custom_hash("hellp")
    print(f"  hash('hello') = 0x{a:08X}")
    print(f"  hash('hellp') = 0x{b:08X}")
    print(f"  bits different: {hamming(a, b)}/32")

    print("\nDISTRIBUTION TEST (10000 strings, count collisions):")
    seen = {}
    collisions = 0
    for i in range(10000):
        s = f"record_{i}"
        h = custom_hash(s)
        if h in seen:
            collisions += 1
            print(f"  collision: {seen[h]} and {s} -> 0x{h:08X}")
        seen[h] = s
    print(f"  {collisions} collisions out of 10000 strings "
          f"({len(seen)} distinct hashes)")

    print("\nCOMPARISON with SHA-256 (built in):")
    import hashlib
    print("  custom  (32 bit) :", f"0x{custom_hash('hello'):08X}")
    print("  sha256 (256 bit) :", hashlib.sha256(b"hello").hexdigest())
    print("  -> a 32-bit hash collides after ~2^16 = 65536 inputs")
    print("     (birthday bound), so it is fine for hash tables but")
    print("     NOT for security. Use SHA-256 for integrity.")
