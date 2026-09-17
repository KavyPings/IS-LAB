"""
LAB 5 - ADDITIONAL 1 (CLIENT)
Splits a message into parts, sends them one by one, then asks the server
for the hash of the reassembled message and verifies it.

RUN:
    python q1_client.py            -> all parts sent, integrity OK
    python q1_client.py drop       -> one part is dropped, integrity FAILS
"""

import socket
import struct
import sys
import hashlib

HOST, PORT = "127.0.0.1", 65433

MESSAGE = ("This complete message is split into several parts before "
           "transmission and reassembled by the server for hashing.")
PARTS = 5


def send_msg(sock, data):
    if isinstance(data, str):
        data = data.encode()
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("closed")
        buf += chunk
    return buf


def recv_msg(sock):
    return recv_exact(sock, struct.unpack(">I", recv_exact(sock, 4))[0])


def split(text, parts):
    """Cut the message into roughly equal pieces."""
    size = -(-len(text) // parts)                 # ceiling division
    return [text[i:i + size] for i in range(0, len(text), size)]


def main(drop_part=False):
    chunks = split(MESSAGE, PARTS)
    print(f"[client] message split into {len(chunks)} parts")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        for i, c in enumerate(chunks):
            if drop_part and i == 2:              # simulate a lost packet
                print(f"[client] DROPPING part {i}: {c!r}")
                continue
            send_msg(s, b"PART" + c.encode())
            print(f"[client] sent part {i}: {c!r}")

        send_msg(s, b"END")
        server_hash = recv_msg(s).decode()
        local_hash = hashlib.sha256(MESSAGE.encode()).hexdigest()

        print(f"\nlocal  SHA-256 (original message) : {local_hash}")
        print(f"server SHA-256 (reassembled)      : {server_hash}")
        print("VERDICT :", "INTEGRITY OK - message reassembled correctly"
              if local_hash == server_hash
              else "INTEGRITY FAILED - a part was lost or altered")
        send_msg(s, "BYE")


if __name__ == "__main__":
    main(drop_part=len(sys.argv) > 1 and sys.argv[1] == "drop")
