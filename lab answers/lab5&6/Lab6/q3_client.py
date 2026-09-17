import socket
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

client = socket.socket()
client.connect(("localhost", 5000))

data = b""

while True:
    part = client.recv(4096)

    if not part:
        break

    data += part

client.close()

pos = 0

key_length = int.from_bytes(data[pos:pos+4], "big")
pos += 4

public_data = data[pos:pos+key_length]
pos += key_length

signature_length = int.from_bytes(data[pos:pos+4], "big")
pos += 4

signature = data[pos:pos+signature_length]
pos += signature_length

message = data[pos:]

public_key = RSA.import_key(public_data)

h = SHA256.new(message)

print("Received Message:", message.decode())

try:
    pkcs1_15.new(public_key).verify(h, signature)
    print("Signature Verified")
except:
    print("Signature Invalid")