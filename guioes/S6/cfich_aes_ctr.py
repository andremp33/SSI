#!/usr/bin/env python3

import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


KEY_SIZE = 32      # AES-256
NONCE_SIZE = 16    # em CTR vamos guardar 16 bytes iniciais


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

    # No modo CTR precisamos de um nonce/counter inicial
    nonce = os.urandom(NONCE_SIZE)

    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Guardar nonce + criptograma
    write_file(fich + ".enc", nonce + ciphertext)


def decrypt_file(fich, fkey):
    key = load_key(fkey)
    data = read_file(fich)

    if len(data) < NONCE_SIZE:
        raise ValueError("Criptograma inválido.")

    # Ler nonce dos primeiros 16 bytes
    nonce = data[:NONCE_SIZE]
    ciphertext = data[NONCE_SIZE:]

    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    write_file(fich + ".dec", plaintext)


def usage():
    print("Uso:")
    print("  python3 cfich_aes_ctr.py setup <fkey>")
    print("  python3 cfich_aes_ctr.py enc <fich> <fkey>")
    print("  python3 cfich_aes_ctr.py dec <fich> <fkey>")


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
    