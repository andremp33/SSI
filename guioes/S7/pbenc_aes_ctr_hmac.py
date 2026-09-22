#!/usr/bin/env python3

import os
import sys
import getpass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac


AES_KEY_SIZE = 32
MAC_KEY_SIZE = 32
NONCE_SIZE = 16
SALT_SIZE = 16
ITERATIONS = 100000
TAG_SIZE = 32   # HMAC-SHA256 -> 32 bytes


def read_file(path):
    with open(path, "rb") as f:
        return f.read()


def write_file(path, data):
    with open(path, "wb") as f:
        f.write(data)


def derive_keys(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE + MAC_KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
    )
    key_material = kdf.derive(password.encode())

    aes_key = key_material[:AES_KEY_SIZE]
    mac_key = key_material[AES_KEY_SIZE:]

    return aes_key, mac_key


def encrypt_file(fich):
    plaintext = read_file(fich)

    password = getpass.getpass("Passphrase: ")
    salt = os.urandom(SALT_SIZE)
    aes_key, mac_key = derive_keys(password, salt)
    nonce = os.urandom(NONCE_SIZE)

    algorithm = algorithms.AES(aes_key)
    cipher = Cipher(algorithm, modes.CTR(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    mac = hmac.HMAC(mac_key, hashes.SHA256())
    mac.update(ciphertext)
    tag = mac.finalize()

    # Guardar salt + nonce + criptograma + tag
    write_file(fich + ".enc", salt + nonce + ciphertext + tag)


def decrypt_file(fich):
    data = read_file(fich)

    if len(data) < SALT_SIZE + NONCE_SIZE + TAG_SIZE:
        raise ValueError("Criptograma inválido.")

    password = getpass.getpass("Passphrase: ")

    salt = data[:SALT_SIZE]
    nonce = data[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    tag = data[-TAG_SIZE:]
    ciphertext = data[SALT_SIZE + NONCE_SIZE:-TAG_SIZE]

    aes_key, mac_key = derive_keys(password, salt)

    mac = hmac.HMAC(mac_key, hashes.SHA256())
    mac.update(ciphertext)

    try:
        mac.verify(tag)
    except InvalidSignature:
        raise ValueError("MAC inválido.")

    algorithm = algorithms.AES(aes_key)
    cipher = Cipher(algorithm, modes.CTR(nonce))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    write_file(fich + ".dec", plaintext)


def usage():
    print("Uso:")
    print("  python3 pbenc_aes_ctr_hmac.py enc <fich>")
    print("  python3 pbenc_aes_ctr_hmac.py dec <fich>")


def main():
    if len(sys.argv) != 3:
        usage()
        sys.exit(1)

    op = sys.argv[1]
    fich = sys.argv[2]

    try:
        if op == "enc":
            encrypt_file(fich)
        elif op == "dec":
            decrypt_file(fich)
        else:
            usage()
            sys.exit(1)

    except FileNotFoundError as e:
        print(f"Erro: ficheiro não encontrado - {e.filename}")
        sys.exit(1)
    except ValueError as e:
        print(f"Erro: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()