import hashlib
import hmac
import random

p = 23
g = 5

alice_private = random.randint(2, p - 2)
bob_private = random.randint(2, p - 2)

alice_public = pow(g, alice_private, p)
bob_public = pow(g, bob_private, p)

alice_secret = pow(
    bob_public,
    alice_private,
    p
)

bob_secret = pow(
    alice_public,
    bob_private,
    p
)

print("Alice Shared Key:", alice_secret)
print("Bob Shared Key:", bob_secret)

message = "Secure Document"

key = str(alice_secret).encode()

signature = hmac.new(
    key,
    message.encode(),
    hashlib.sha256
).hexdigest()

bob_key = str(bob_secret).encode()

verify = hmac.new(
    bob_key,
    message.encode(),
    hashlib.sha256
).hexdigest()

print("Message:", message)
print("Signature:", signature)

if signature == verify:
    print("Verification Successful")
else:
    print("Verification Failed")