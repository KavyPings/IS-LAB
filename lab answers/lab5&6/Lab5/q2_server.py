import socket

def hash_function(text):
    h = 5381

    for ch in text:
        h = ((h * 33) + ord(ch)) & 0xFFFFFFFF

    return h

server = socket.socket()
server.bind(("localhost", 5000))
server.listen(1)

print("Server waiting for connection...")

conn, addr = server.accept()

data = conn.recv(1024).decode()

print("Received data:", data)

server_hash = hash_function(data)

print("Server hash:", server_hash)

conn.send(str(server_hash).encode())

conn.close()
server.close()