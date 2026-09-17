"""
LAB 5 - ADDITIONAL 1 (SERVER)
The client sends a message in MULTIPLE PARTS. The server reassembles the
parts, computes the hash of the reassembled message, and sends that hash
back. The client compares it with the hash of its original message.

RUN THE SERVER FIRST:
    python q1_server.py
THEN:
    python q1_client.py            (all parts arrive -> OK)
    python q1_client.py drop       (one part lost    -> FAILED)

PROTOCOL
    b"PART" + chunk   -> append the chunk to the buffer
    b"END"            -> hash the buffer, send the digest, reset
    b"BYE"            -> close
"""

import socket
import struct
import hashlib

HOST, PORT = "127.0.0.1", 65433


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


def send_msg(sock, data):
    if isinstance(data, str):
        data = data.encode()
    sock.sendall(struct.pack(">I", len(data)) + data)


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        print(f"[server] multipart reassembly server on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            print(f"[server] connection from {addr}")
            buffer = b""                          # accumulates the parts
            with conn:
                try:
                    while True:
                        data = recv_msg(conn)
                        if data == b"BYE":
                            print("[server] client finished\n")
                            break
                        if data.startswith(b"PART"):
                            chunk = data[4:]      # strip the 4-byte tag
                            buffer += chunk
                            print(f"[server] part received: {chunk!r} "
                                  f"(buffer now {len(buffer)} bytes)")
                        elif data == b"END":
                            digest = hashlib.sha256(buffer).hexdigest()
                            print(f"[server] reassembled: {buffer.decode()}")
                            print(f"[server] SHA-256    : {digest}")
                            send_msg(conn, digest)
                            buffer = b""          # ready for the next message
                except ConnectionError:
                    print("[server] connection lost\n")


if __name__ == "__main__":
    main()
