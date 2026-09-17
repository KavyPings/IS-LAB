import socket
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

key = RSA.generate(2048)

private_key = key
public_key = key.publickey()

message = b"Confidential Document"

h = SHA256.new(message)
signature = pkcs1_15.new(private_key).sign(h)

server = socket.socket()
server.bind(("localhost", 5000))
server.listen(1)

print("Waiting for client...")

conn, addr = server.accept()

public_data = public_key.export_key()

conn.sendall(
    len(public_data).to_bytes(4, "big") +
    public_data +
    len(signature).to_bytes(4, "big") +
    signature +
    message
)

print("Document and signature sent")

conn.close()
server.close()