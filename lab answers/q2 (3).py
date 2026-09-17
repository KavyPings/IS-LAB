PLAINTEXT = "THEHOUSEISBEINGSOLDTONIGHT"

def vigenere_encrypt(text, key):
    key = key.upper()
    cipher = ""

    for i in range(len(text)):
        p = ord(text[i]) - ord('A')
        k = ord(key[i % len(key)]) - ord('A')
        cipher += chr((p + k) % 26 + ord('A'))

    return cipher

def vigenere_decrypt(cipher, key):
    key = key.upper()
    text = ""

    for i in range(len(cipher)):
        c = ord(cipher[i]) - ord('A')
        k = ord(key[i % len(key)]) - ord('A')
        text += chr((c - k) % 26 + ord('A'))

    return text

def autokey_encrypt(text, key):
    key_stream = chr(key + ord('A')) + text[:-1]
    cipher = ""

    for i in range(len(text)):
        p = ord(text[i]) - ord('A')
        k = ord(key_stream[i]) - ord('A')
        cipher += chr((p + k) % 26 + ord('A'))

    return cipher


def autokey_decrypt(cipher, key):
    plaintext = ""
    prev = key

    for ch in cipher:
        c = ord(ch) - ord('A')
        p = (c - prev) % 26
        plaintext += chr(p + ord('A'))
        prev = p

    return plaintext

while True:

    print("\n===== MENU =====")
    print("1. Vigenere Cipher")
    print("2. Autokey Cipher")
    print("3. Exit")

    choice = int(input("Enter your choice: "))

    if choice == 1:
        key = "DOLLARS"

        cipher = vigenere_encrypt(PLAINTEXT, key)
        plain = vigenere_decrypt(cipher, key)

        print("\nPlaintext :", PLAINTEXT)
        print("Key       :", key)
        print("Ciphertext:", cipher)
        print("Decrypted :", plain)

    elif choice == 2:
        key = 7

        cipher = autokey_encrypt(PLAINTEXT, key)
        plain = autokey_decrypt(cipher, key)

        print("\nPlaintext :", PLAINTEXT)
        print("Key       :", key)
        print("Ciphertext:", cipher)
        print("Decrypted :", plain)

    elif choice == 3:
        print("Exiting...")
        break

    else:
        print("Invalid Choice!")