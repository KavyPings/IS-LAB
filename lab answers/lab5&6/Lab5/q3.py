import hashlib
import random
import string
import time

data = []

for i in range(100):
    length = random.randint(10, 50)
    text = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    data.append(text)


def calculate_hash(algorithm):
    hashes = []

    start = time.perf_counter()

    for text in data:
        h = hashlib.new(algorithm)
        h.update(text.encode())
        hashes.append(h.hexdigest())

    end = time.perf_counter()

    return hashes, end - start


def find_collisions(hashes):
    seen = set()
    collisions = 0

    for h in hashes:
        if h in seen:
            collisions += 1
        else:
            seen.add(h)

    return collisions


md5_hashes, md5_time = calculate_hash("md5")
sha1_hashes, sha1_time = calculate_hash("sha1")
sha256_hashes, sha256_time = calculate_hash("sha256")

md5_collisions = find_collisions(md5_hashes)
sha1_collisions = find_collisions(sha1_hashes)
sha256_collisions = find_collisions(sha256_hashes)


print("Number of strings:", len(data))

print("\nMD5")
print("Time:", md5_time, "seconds")
print("Collisions:", md5_collisions)

print("\nSHA-1")
print("Time:", sha1_time, "seconds")
print("Collisions:", sha1_collisions)

print("\nSHA-256")
print("Time:", sha256_time, "seconds")
print("Collisions:", sha256_collisions)

print("\nComparison")
print("--------------------------------")
print("Algorithm   Time(s)   Collisions")
print("--------------------------------")
print("MD5        ", md5_time, "   ", md5_collisions)
print("SHA-1      ", sha1_time, "   ", sha1_collisions)
print("SHA-256    ", sha256_time, "   ", sha256_collisions)