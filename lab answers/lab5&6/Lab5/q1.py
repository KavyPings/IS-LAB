def hash_function(text):
    hash_value = 5381

    for ch in text:
        hash_value = ((hash_value * 33) + ord(ch)) & 0xFFFFFFFF

    return hash_value


text = input("Enter a string: ")

result = hash_function(text)

print("Hash value:", result)