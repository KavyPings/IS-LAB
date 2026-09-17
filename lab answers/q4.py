import os
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def benchmark_rsa(file_data):

    start = time.perf_counter()
    rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_pub = rsa_priv.public_key()
    gen_time = time.perf_counter() - start

    start = time.perf_counter()
    aes_key = os.urandom(32)
    iv = os.urandom(12)
    encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv)).encryptor()
    ciphertext = encryptor.update(file_data) + encryptor.finalize()
    tag = encryptor.tag

    encrypted_aes_key = rsa_pub.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    enc_time = time.perf_counter() - start

    start = time.perf_counter()
    decrypted_aes_key = rsa_priv.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    decryptor = Cipher(algorithms.AES(decrypted_aes_key), modes.GCM(iv, tag)).decryptor()
    _ = decryptor.update(ciphertext) + decryptor.finalize()
    dec_time = time.perf_counter() - start

    return gen_time, enc_time, dec_time


def benchmark_ecc(file_data):

    start = time.perf_counter()
    ecc_priv = ec.generate_private_key(ec.SECP256R1())
    ecc_pub = ecc_priv.public_key()
    gen_time = time.perf_counter() - start

    start = time.perf_counter()
    ephemeral_priv = ec.generate_private_key(ec.SECP256R1())
    ephemeral_pub = ephemeral_priv.public_key()
    shared_key = ephemeral_priv.exchange(ec.ECDH(), ecc_pub)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'file-transfer-ecies'
    ).derive(shared_key)

    iv = os.urandom(12)
    encryptor = Cipher(algorithms.AES(derived_key), modes.GCM(iv)).encryptor()
    ciphertext = encryptor.update(file_data) + encryptor.finalize()
    tag = encryptor.tag
    enc_time = time.perf_counter() - start

    start = time.perf_counter()
    shared_key_dec = ecc_priv.exchange(ec.ECDH(), ephemeral_pub)
    derived_key_dec = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'file-transfer-ecies'
    ).derive(shared_key_dec)

    decryptor = Cipher(algorithms.AES(derived_key_dec), modes.GCM(iv, tag)).decryptor()
    _ = decryptor.update(ciphertext) + decryptor.finalize()
    dec_time = time.perf_counter() - start

    return gen_time, enc_time, dec_time
if __name__ == "__main__":
    file_1mb = os.urandom(1 * 1024 * 1024)
    file_10mb = os.urandom(10 * 1024 * 1024)

    print("--- BENCHMARK RESULTS ---")

    rsa_gen, rsa_enc_1, rsa_dec_1 = benchmark_rsa(file_1mb)
    ecc_gen, ecc_enc_1, ecc_dec_1 = benchmark_ecc(file_1mb)

    _, rsa_enc_10, rsa_dec_10 = benchmark_rsa(file_10mb)
    _, ecc_enc_10, ecc_dec_10 = benchmark_ecc(file_10mb)

    print(f"RSA-2048 Key Generation Time: {rsa_gen:.4f} s")
    print(f"ECC-P256 Key Generation Time: {ecc_gen:.4f} s\n")

    print(f"1 MB File -> RSA Encrypt: {rsa_enc_1:.4f}s | Decrypt: {rsa_dec_1:.4f}s")
    print(f"1 MB File -> ECC Encrypt: {ecc_enc_1:.4f}s | Decrypt: {ecc_dec_1:.4f}s\n")

    print(f"10 MB File -> RSA Encrypt: {rsa_enc_10:.4f}s | Decrypt: {rsa_dec_10:.4f}s")
    print(f"10 MB File -> ECC Encrypt: {ecc_enc_10:.4f}s | Decrypt: {ecc_dec_10:.4f}s")