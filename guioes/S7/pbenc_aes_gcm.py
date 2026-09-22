#!/usr/bin/env python3

import os
import sys
import getpass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


KEY_SIZE = 32
NONCE_SIZE = 12
SALT_SIZE = 16
ITERATIONS = 100000


def read_file(path):
    with open(path, "rb") as f:
        return f.read()


def write_file(path, data):
    with open(path, "wb") as f:
        f.write(data)


def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(password.encode())


def encrypt_file(fich):
    plaintext = read_file(fich)

    password = getpass.getpass("Passphrase: ")
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    nonce = os.urandom(NONCE_SIZE)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    # Guardar salt + nonce + criptograma+tag
    write_file(fich + ".enc", salt + nonce + ciphertext)


def decrypt_file(fich):
    data = read_file(fich)

    if len(data) < SALT_SIZE + NONCE_SIZE + 16:
        raise ValueError("Criptograma inválido.")

    password = getpass.getpass("Passphrase: ")

    salt = data[:SALT_SIZE]
    nonce = data[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = data[SALT_SIZE + NONCE_SIZE:]

    key = derive_key(password, salt)

    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise ValueError("Tag inválida.")

    write_file(fich + ".dec", plaintext)


def usage():
    print("Uso:")
    print("  python3 pbenc_aes_gcm.py enc <fich>")
    print("  python3 pbenc_aes_gcm.py dec <fich>")


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