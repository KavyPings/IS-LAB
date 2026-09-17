import numpy as np

PLAINTEXT = "WE LIVE IN AN INSECURE WORLD"

KEY = np.array([[3, 3],
                [2, 7]])

text = PLAINTEXT.replace(" ", "").upper()

if len(text) % 2 != 0:
    text += "X"

cipher = ""

for i in range(0, len(text), 2):
    block = np.array([
        ord(text[i]) - ord('A'),
        ord(text[i + 1]) - ord('A')
    ])

    result = np.dot(KEY, block) % 26

    cipher += chr(result[0] + ord('A'))
    cipher += chr(result[1] + ord('A'))

print("Plaintext :", text)
print("Key Matrix:")
print(KEY)
print("Ciphertext:", cipher)