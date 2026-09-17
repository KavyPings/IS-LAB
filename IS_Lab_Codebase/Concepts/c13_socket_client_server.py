"""
CONCEPT 13 : SOCKET CLIENT-SERVER TEMPLATE
(Lab 5 Q2 + additional Q1, Lab 6 Q3)

Run the SERVER first in one terminal, the CLIENT in another:
    python c13_socket_client_server.py server
    python c13_socket_client_server.py client

PROTOCOL USED HERE (keep it this simple in an exam):
    every message is sent as   4-byte big-endian length  +  payload
    -> recv_msg() always gets the whole message, never a half one.
"""

import socket
import sys
import hashlib
import struct

HOST, PORT = "127.0.0.1", 65432


# ---------------------------------------------------------------------------
# FRAMING HELPERS - copy these two functions into any socket answer
# ---------------------------------------------------------------------------

def send_msg(sock, data):
    """Send length first, then the data."""
    if isinstance(data, str):
        data = data.encode()
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_exact(sock, n):
    """Keep reading until exactly n bytes arrive (recv can return less)."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf


def recv_msg(sock):
    """Read the 4-byte length, then that many bytes."""
    length = struct.unpack(">I", recv_exact(sock, 4))[0]
    return recv_exact(sock, length)


# ---------------------------------------------------------------------------
# SERVER : receives data, hashes it, sends the hash back
# ---------------------------------------------------------------------------

def run_server(host=HOST, port=PORT):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen()
        print(f"[server] listening on {host}:{port}")
        while True:
            conn, addr = s.accept()
            with conn:
                print(f"[server] client {addr} connected")
                try:
                    while True:
                        data = recv_msg(conn)
                        if data == b"BYE":
                            print("[server] client said BYE")
                            break
                        digest = hashlib.sha256(data).hexdigest()
                        print(f"[server] got {len(data)} bytes -> {digest[:16]}...")
                        send_msg(conn, digest)          # send the hash back
                except ConnectionError:
                    print("[server] client disconnected")


# ---------------------------------------------------------------------------
# CLIENT : sends data, compares the returned hash with its own
# ---------------------------------------------------------------------------

def run_client(messages=None, host=HOST, port=PORT, corrupt=False):
    messages = messages or ["Hello secure world", "Second message"]
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        for msg in messages:
            payload = msg.encode()
            if corrupt:
                payload = payload[:-1] + bytes([payload[-1] ^ 0x01])  # flip a bit
            send_msg(s, payload)
            received = recv_msg(s).decode()
            local = hashlib.sha256(msg.encode()).hexdigest()
            print(f"\nmessage  : {msg}")
            print(f"local    : {local}")
            print(f"server   : {received}")
            print("INTEGRITY:", "OK" if local == received else "FAILED (tampered)")
        send_msg(s, "BYE")


# ---------------------------------------------------------------------------
# MULTI-PART VARIANT (Lab 5 additional Q1)
#   client sends the message in chunks; server reassembles then hashes.
# ---------------------------------------------------------------------------

def run_client_multipart(message, parts=4, host=HOST, port=PORT):
    """Sends 'PART <data>' pieces then 'END'; server replies with the hash."""
    size = max(1, len(message) // parts)
    chunks = [message[i:i + size] for i in range(0, len(message), size)]
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        for c in chunks:
            send_msg(s, b"PART" + c.encode())
            print("[client] sent part:", c)
        send_msg(s, b"END")
        digest = recv_msg(s).decode()
        local = hashlib.sha256(message.encode()).hexdigest()
        print("server hash:", digest)
        print("local  hash:", local)
        print("INTEGRITY  :", "OK" if digest == local else "FAILED")
        send_msg(s, "BYE")


def run_server_multipart(host=HOST, port=PORT):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen()
        print(f"[server] multipart mode on {host}:{port}")
        while True:
            conn, addr = s.accept()
            buffer = b""
            with conn:
                try:
                    while True:
                        data = recv_msg(conn)
                        if data == b"BYE":
                            break
                        if data == b"END":
                            digest = hashlib.sha256(buffer).hexdigest()
                            print(f"[server] reassembled: {buffer.decode()}")
                            send_msg(conn, digest)
                            buffer = b""
                        elif data.startswith(b"PART"):
                            buffer += data[4:]          # strip the 'PART' tag
                except ConnectionError:
                    pass


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "server"
    if mode == "server":
        run_server()
    elif mode == "client":
        run_client()
    elif mode == "client-bad":
        run_client(corrupt=True)            # shows tamper detection
    elif mode == "server-mp":
        run_server_multipart()
    elif mode == "client-mp":
        run_client_multipart("This long message is sent in several parts")
    else:
        print("usage: server | client | client-bad | server-mp | client-mp")
