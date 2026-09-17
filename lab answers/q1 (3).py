PLAINTEXT = "IAMLEARNINGINFORMATIONSECURITY"

def char_to_num(ch):
    return ord(ch) - ord('A')

def num_to_char(num):
    return chr((num % 26) + ord('A'))

def mod_inverse(key):
    for i in range(26):
        if (key * i) % 26 == 1:
            return i
    return None

def additive_encrypt(text, key):
    cipher = ""
    for ch in text:
        cipher += num_to_char(char_to_num(ch) + key)
    return cipher

def additive_decrypt(cipher, key):
    text = ""
    for ch in cipher:
        text += num_to_char(char_to_num(ch) - key)
    return text

def multiplicative_encrypt(text, key):
    cipher = ""
    for ch in text:
        cipher += num_to_char(char_to_num(ch) * key)
    return cipher

def multiplicative_decrypt(cipher, key):
    inverse = mod_inverse(key)
    text = ""
    for ch in cipher:
        text += num_to_char(char_to_num(ch) * inverse)
    return text

def affine_encrypt(text, a, b):
    cipher = ""
    for ch in text:
        cipher += num_to_char(a * char_to_num(ch) + b)
    return cipher

def affine_decrypt(cipher, a, b):
    inverse = mod_inverse(a)
    text = ""
    for ch in cipher:
        text += num_to_char(inverse * (char_to_num(ch) - b))
    return text

while True:
    print("\nMENU")
    print("1. Additive Cipher (Key = 20)")
    print("2. Multiplicative Cipher (Key = 15)")
    print("3. Affine Cipher (15, 20)")
    print("4. Exit")

    choice = int(input("Enter your choice: "))

    if choice == 1:
        cipher = additive_encrypt(PLAINTEXT, 20)
        print("\nPlaintext :", PLAINTEXT)
        print("Ciphertext:", cipher)
        print("Decrypted :", additive_decrypt(cipher, 20))

    elif choice == 2:
        cipher = multiplicative_encrypt(PLAINTEXT, 15)
        print("\nPlaintext :", PLAINTEXT)
        print("Ciphertext:", cipher)
        print("Decrypted :", multiplicative_decrypt(cipher, 15))

    elif choice == 3:
        cipher = affine_encrypt(PLAINTEXT, 15, 20)
        print("\nPlaintext :", PLAINTEXT)
        print("Ciphertext:", cipher)
        print("Decrypted :", affine_decrypt(cipher, 15, 20))

    elif choice == 4:
        print("Exiting...")
        break

    else:
        print("Invalid Choice!")