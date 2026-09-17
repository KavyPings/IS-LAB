import time
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def diffie_hellman_benchmark():

    start = time.perf_counter()

    parameters = dh.generate_parameters(
        generator=2,
        key_size=2048
    )

    parameter_time = time.perf_counter() - start

    start = time.perf_counter()

    private_key_a = parameters.generate_private_key()
    public_key_a = private_key_a.public_key()

    keygen_a_time = time.perf_counter() - start
    start = time.perf_counter()

    private_key_b = parameters.generate_private_key()
    public_key_b = private_key_b.public_key()

    keygen_b_time = time.perf_counter() - start

    start = time.perf_counter()

    shared_secret_a = private_key_a.exchange(public_key_b)

    exchange_a_time = time.perf_counter() - start

    start = time.perf_counter()

    shared_secret_b = private_key_b.exchange(public_key_a)

    exchange_b_time = time.perf_counter() - start

    derived_key_a = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'p2p-file-sharing'
    ).derive(shared_secret_a)

    derived_key_b = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'p2p-file-sharing'
    ).derive(shared_secret_b)

    print("\n===== DIFFIE-HELLMAN KEY EXCHANGE =====")

    print(f"Parameter Generation Time : {parameter_time:.6f} seconds")
    print(f"Peer A Key Generation     : {keygen_a_time:.6f} seconds")
    print(f"Peer B Key Generation     : {keygen_b_time:.6f} seconds")

    print(f"\nPeer A Key Exchange Time   : {exchange_a_time:.6f} seconds")
    print(f"Peer B Key Exchange Time   : {exchange_b_time:.6f} seconds")

    print("\nShared Secret Verification:")
    print("Peer A and Peer B secrets match:",
          shared_secret_a == shared_secret_b)

    print("Derived Symmetric Keys Match:",
          derived_key_a == derived_key_b)

    print("\nDerived 256-bit Shared Key:")
    print(derived_key_a.hex())


if __name__ == "__main__":
    diffie_hellman_benchmark()