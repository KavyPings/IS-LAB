known_plaintext = "YES"
known_ciphertext = "CIW"
ciphertext = "XVIEWYWI"

key = (ord(known_ciphertext[0]) - ord(known_plaintext[0])) % 26

print("Known Plaintext :", known_plaintext)
print("Known Ciphertext:", known_ciphertext)
print("Attack Type     : Known Plaintext Attack")
print("Shift Key       :", key)

plaintext = ""

for ch in ciphertext:
    p = (ord(ch) - ord('A') - key) % 26
    plaintext += chr(p + ord('A'))

print("\nCiphertext :", ciphertext)
print("Plaintext  :", plaintext)