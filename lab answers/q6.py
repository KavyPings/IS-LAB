ciphertext = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"

a = 5
b = 6

def mod_inverse(a):
    for i in range(26):
        if (a * i) % 26 == 1:
            return i
    return None

a_inv = mod_inverse(a)

plaintext = ""

for ch in ciphertext:
    if ch.isalpha():
        c = ord(ch) - ord('A')
        p = (a_inv * (c - b)) % 26
        plaintext += chr(p + ord('A'))
    else:
        plaintext += ch

print("Affine Key (a, b):", (a, b))
print("Ciphertext :", ciphertext)
print("Plaintext  :", plaintext)