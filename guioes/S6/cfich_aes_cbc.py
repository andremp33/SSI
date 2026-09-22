#!/usr/bin/env python3

import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7


KEY_SIZE = 32      # AES-256
BLOCK_SIZE = 16    # 16 bytes = 128 bits


def read_file(path):
    with open(path, "rb") as f:
        return f.read()


def write_file(path, data):
    with open(path, "wb") as f:
        f.write(data)


def setup_key_file(fkey):
    key = os.urandom(KEY_SIZE)
    write_file(fkey, key)


def load_key(fkey):
    key = read_file(fkey)
    if len(key) != KEY_SIZE:
        raise ValueError("Chave inválida: deve ter 32 bytes.")
    return key


def encrypt_file(fich, fkey):
    key = load_key(fkey)
    plaintext = read_file(fich)

    # No modo CBC é preciso um IV aleatório
    iv = os.urandom(BLOCK_SIZE)

    # Padding PKCS7 para garantir múltiplo de 16 bytes
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Guardar IV + criptograma
    write_file(fich + ".enc", iv + ciphertext)


def decrypt_file(fich, fkey):
    key = load_key(fkey)
    data = read_file(fich)

    if len(data) < BLOCK_SIZE:
        raise ValueError("Criptograma inválido.")

    # Ler IV dos primeiros 16 bytes
    iv = data[:BLOCK_SIZE]
    ciphertext = data[BLOCK_SIZE:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remover padding
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    write_file(fich + ".dec", plaintext)


def usage():
    print("Uso:")
    print("  python3 cfich_aes_cbc.py setup <fkey>")
    print("  python3 cfich_aes_cbc.py enc <fich> <fkey>")
    print("  python3 cfich_aes_cbc.py dec <fich> <fkey>")


def main():
    if len(sys.argv) < 3:
        usage()
        sys.exit(1)

    op = sys.argv[1]

    try:
        if op == "setup":
            if len(sys.argv) != 3:
                usage()
                sys.exit(1)
            fkey = sys.argv[2]
            setup_key_file(fkey)

        elif op == "enc":
            if len(sys.argv) != 4:
                usage()
                sys.exit(1)
            fich = sys.argv[2]
            fkey = sys.argv[3]
            encrypt_file(fich, fkey)

        elif op == "dec":
            if len(sys.argv) != 4:
                usage()
                sys.exit(1)
            fich = sys.argv[2]
            fkey = sys.argv[3]
            decrypt_file(fich, fkey)

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