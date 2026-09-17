KEY = "GUIDANCE"
PLAINTEXT = "THE KEY IS HIDDEN UNDER THE DOOR PAD"

def generate_matrix(key):
    key = key.upper().replace("J", "I")
    matrix = []
    used = set()

    for ch in key:
        if ch.isalpha() and ch not in used:
            matrix.append(ch)
            used.add(ch)

    for ch in "ABCDEFGHIKLMNOPQRSTUVWXYZ":   # J omitted
        if ch not in used:
            matrix.append(ch)
            used.add(ch)

    return [matrix[i:i+5] for i in range(0, 25, 5)]


def prepare_text(text):
    text = text.upper().replace(" ", "").replace("J", "I")

    result = ""
    i = 0

    while i < len(text):
        a = text[i]

        if i + 1 == len(text):
            b = "X"
            i += 1
        else:
            b = text[i + 1]

            if a == b:
                b = "X"
                i += 1
            else:
                i += 2

        result += a + b

    if len(result) % 2 != 0:
        result += "X"

    return result


def find(matrix, ch):
    for i in range(5):
        for j in range(5):
            if matrix[i][j] == ch:
                return i, j


def encrypt(matrix, text):
    cipher = ""

    for i in range(0, len(text), 2):
        a = text[i]
        b = text[i + 1]

        r1, c1 = find(matrix, a)
        r2, c2 = find(matrix, b)

        if r1 == r2:
            cipher += matrix[r1][(c1 + 1) % 5]
            cipher += matrix[r2][(c2 + 1) % 5]

        elif c1 == c2:
            cipher += matrix[(r1 + 1) % 5][c1]
            cipher += matrix[(r2 + 1) % 5][c2]

        else:
            cipher += matrix[r1][c2]
            cipher += matrix[r2][c1]

    return cipher


matrix = generate_matrix(KEY)

print("Playfair Matrix:")
for row in matrix:
    print(" ".join(row))

prepared = prepare_text(PLAINTEXT)
cipher = encrypt(matrix, prepared)

print("\nPrepared Plaintext :", prepared)
print("Ciphertext         :", cipher)