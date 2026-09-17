"""
LAB 6 - EXERCISE 3 (CLIENT)
Generates an RSA key pair, registers the public key with the server,
signs a document and asks the server to verify it.

RUN:
    python q3_client.py            valid signature
    python q3_client.py tamper     document changed after signing
    python q3_client.py forge      signed with a different (wrong) key
"""

import socket
import struct
import json
import sys
import base64

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

HOST, PORT = "127.0.0.1", 65434
DOCUMENT = "Purchase agreement PA-2026-0912 for 500 units"


def send_json(sock, obj):
    data = json.dumps(obj).encode()
    sock.sendall(struct.pack(">I", len(data)) + data)


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


def main(mode="ok"):
    print("[client] generating RSA-2048 key pair ...")
    key = RSA.generate(2048)
    signing_key = RSA.generate(2048) if mode == "forge" else key   # wrong key

    signature = pkcs1_15.new(signing_key).sign(SHA256.new(DOCUMENT.encode()))
    sent_doc = DOCUMENT + " (altered)" if mode == "tamper" else DOCUMENT

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        send_json(s, {"action": "register", "name": "ClientA",
                      "pubkey": base64.b64encode(key.publickey().export_key()).decode()})
        print("[client]", recv_json(s)["msg"])

        send_json(s, {"action": "verify", "name": "ClientA",
                      "document": sent_doc,
                      "signature": base64.b64encode(signature).decode()})
        r = recv_json(s)
        print(f"\nmode          : {mode}")
        print(f"document sent : {sent_doc}")
        print(f"server says   : {'VALID' if r['valid'] else 'INVALID'}")
        print(f"recorded      : {r['entry']['time']}  hash {r['entry']['hash'][:32]}...")

        send_json(s, {"action": "ledger"})
        print("\n[client] server ledger:")
        for e in recv_json(s)["ledger"]:
            print(f"   {e['time']} | {e['signer']:<8} | "
                  f"{'VALID  ' if e['valid'] else 'INVALID'} | {e['document'][:45]}")

        send_json(s, {"action": "bye"})
        recv_json(s)

    print("""
OBSERVATION AND ANALYSIS
  * The signature travels with the document; the server needs only the
    signer's PUBLIC key, which it received in advance.
  * Changing a single character of the document makes the signature fail
    (mode 'tamper') - this is INTEGRITY.
  * Signing with another key fails against the registered public key
    (mode 'forge') - this is AUTHENTICATION.
  * The signer cannot later deny signing, because only their private key
    could produce a signature that verifies - this is NON-REPUDIATION.
  * The signature does NOT hide the document. For confidentiality the
    document must also be encrypted (see the sample question).""")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "ok")
