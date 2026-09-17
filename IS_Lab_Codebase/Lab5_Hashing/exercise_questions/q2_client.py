"""
LAB 5 - EXERCISE 2 (CLIENT)
Sends data to the server, receives the server's hash, and compares it with
the hash computed locally. Detects corruption/tampering.

RUN:
    python q2_client.py            -> clean data, hashes match
    python q2_client.py corrupt    -> one bit flipped in transit, mismatch
"""

import socket
import struct
import sys
import hashlib

HOST, PORT = "127.0.0.1", 65432

MESSAGES = [
    "Integrity of this message must be verified",
    "Second block of transmitted data",
    "Information Security Lab - hashing demo",
]


def send_msg(sock, data):
    if isinstance(data, str):
        data = data.encode()
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("server closed the connection")
        buf += chunk
    return buf


def recv_msg(sock):
    return recv_exact(sock, struct.unpack(">I", recv_exact(sock, 4))[0])


def corrupt(data):
    """Simulate tampering / a transmission error: flip the last bit."""
    return data[:-1] + bytes([data[-1] ^ 0x01])


def main(tamper=False):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print(f"[client] connected to {HOST}:{PORT}"
              f"{'  (CORRUPTING DATA IN TRANSIT)' if tamper else ''}\n")
        for msg in MESSAGES:
            local = hashlib.sha256(msg.encode()).hexdigest()   # hash BEFORE sending
            payload = corrupt(msg.encode()) if tamper else msg.encode()
            send_msg(s, payload)
            remote = recv_msg(s).decode()                      # hash from server

            print(f"message        : {msg}")
            print(f"local  SHA-256 : {local}")
            print(f"server SHA-256 : {remote}")
            print("VERDICT        :",
                  "INTEGRITY OK" if local == remote
                  else "INTEGRITY FAILED - data was corrupted or tampered with")
            print()
        send_msg(s, "BYE")


if __name__ == "__main__":
    main(tamper=len(sys.argv) > 1 and sys.argv[1] == "corrupt")
