import socket

def hash_function(text):
    h = 5381

    for ch in text:
        h = ((h * 33) + ord(ch)) & 0xFFFFFFFF

    return h

client = socket.socket()
client.connect(("localhost", 5000))

data = input("Enter data: ")

local_hash = hash_function(data)

print("Original data:", data)
print("Local hash:", local_hash)

client.send(data.encode())

server_hash = int(client.recv(1024).decode())

print("Server hash:", server_hash)

if local_hash == server_hash:
    print("Data Integrity Verified")
    print("No corruption or tampering detected")
else:
    print("Data Integrity Failed")
    print("Data may be corrupted or tampered with")

client.close()