"""
LAB 6 - EXERCISE 3 (SERVER)
"Try the same in a client-server based scenario and record your
 observation and analysis."

The server acts as the VERIFIER / document authority:
  * a client registers its public key,
  * a client submits {document, signature},
  * the server verifies the signature and records the result,
  * the server can list all verified documents.

RUN THE SERVER FIRST:
    python q3_server.py
THEN:
    python q3_client.py            -> valid signature accepted
    python q3_client.py tamper     -> document modified, REJECTED
    python q3_client.py forge      -> signed with the wrong key, REJECTED
"""

import socket
import struct
import json
import base64
from datetime import datetime

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

HOST, PORT = "127.0.0.1", 65434


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        c = sock.recv(n - len(buf))
        if not c:
            raise ConnectionError("closed")
        buf += c
    return buf


def recv_json(sock):
    return json.loads(recv_exact(sock, struct.unpack(">I", recv_exact(sock, 4))[0]))


def send_json(sock, obj):
    data = json.dumps(obj).encode()
    sock.sendall(struct.pack(">I", len(data)) + data)


PUBLIC_KEYS = {}        # client name -> RSA public key
LEDGER = []             # verification results


def handle(conn, addr):
    while True:
        req = recv_json(conn)
        action = req.get("action")

        if action == "register":
            PUBLIC_KEYS[req["name"]] = RSA.import_key(base64.b64decode(req["pubkey"]))
            print(f"[server] registered public key for {req['name']}")
            send_json(conn, {"ok": True, "msg": "public key registered"})

        elif action == "verify":
            name = req["name"]
            doc = req["document"]
            sig = base64.b64decode(req["signature"])
            pub = PUBLIC_KEYS.get(name)
            if pub is None:
                send_json(conn, {"ok": False, "msg": "unknown signer"})
                continue
            try:
                pkcs1_15.new(pub).verify(SHA256.new(doc.encode()), sig)
                valid = True
            except (ValueError, TypeError):
                valid = False
            entry = {"signer": name, "document": doc, "valid": valid,
                     "hash": SHA256.new(doc.encode()).hexdigest(),
                     "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
            LEDGER.append(entry)
            print(f"[server] {name}: {'VALID' if valid else 'INVALID'} - {doc[:40]}")
            send_json(conn, {"ok": True, "valid": valid, "entry": entry})

        elif action == "ledger":
            send_json(conn, {"ok": True, "ledger": LEDGER})

        elif action == "bye":
            send_json(conn, {"ok": True})
            return


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        print(f"[server] document authority listening on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            print(f"[server] client {addr} connected")
            with conn:
                try:
                    handle(conn, addr)
                except ConnectionError:
                    pass
            print("[server] client disconnected\n")


if __name__ == "__main__":
    main()
