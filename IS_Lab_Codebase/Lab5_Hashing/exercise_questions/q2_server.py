"""
LAB 5 - EXERCISE 2 (SERVER)
Socket programming: the server receives data, computes its hash, and sends
the hash back so the client can verify integrity.

RUN THE SERVER FIRST:
    python q2_server.py
THEN IN ANOTHER TERMINAL:
    python q2_client.py            (clean transmission -> OK)
    python q2_client.py corrupt    (bit flipped       -> FAILED)

MESSAGE FRAMING
  TCP is a byte stream: one recv() can return half a message or two messages.
  So every message is sent as  4-byte length + payload, and recv_exact()
  loops until it has exactly that many bytes.
"""

import socket
import struct
import hashlib

HOST, PORT = "127.0.0.1", 65432


def recv_exact(sock, n):
    """Read exactly n bytes, looping because recv() may return fewer."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("client closed the connection")
        buf += chunk
    return buf


def recv_msg(sock):
    length = struct.unpack(">I", recv_exact(sock, 4))[0]   # 4-byte length
    return recv_exact(sock, length)


def send_msg(sock, data):
    if isinstance(data, str):
        data = data.encode()
    sock.sendall(struct.pack(">I", len(data)) + data)      # length + payload


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        print(f"[server] listening on {HOST}:{PORT}  (Ctrl+C to stop)")
        while True:
            conn, addr = s.accept()
            print(f"[server] connection from {addr}")
            with conn:
                try:
                    while True:
                        data = recv_msg(conn)
                        if data == b"BYE":
                            print("[server] client finished\n")
                            break
                        digest = hashlib.sha256(data).hexdigest()
                        print(f"[server] received {len(data):3d} bytes: "
                              f"{data.decode(errors='replace')[:40]}")
                        print(f"[server] SHA-256 = {digest}")
                        send_msg(conn, digest)          # send the hash back
                except ConnectionError:
                    print("[server] connection lost\n")


if __name__ == "__main__":
    main()
