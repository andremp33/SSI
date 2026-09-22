import os
import sys
import hmac
from cryptography.hazmat.primitives import hashes


KEY_SIZE = 32  # 32 bytes = 256 bits


def usage():
    print("Uso:")
    print("  python3 mac_sha256.py setup <fkey>")
    print("  python3 mac_sha256.py mac <fich> <fkey>")
    print("  python3 mac_sha256.py ver <fich> <fkey>")
    sys.exit(1)


def read_file(path):
    with open(path, "rb") as f:
        return f.read()


def write_file(path, data):
    with open(path, "wb") as f:
        f.write(data)


def compute_prefix_mac(key, msg):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(key)
    digest.update(msg)
    return digest.finalize()


def do_setup(fkey):
    key = os.urandom(KEY_SIZE)
    write_file(fkey, key)


def do_mac(fich, fkey):
    key = read_file(fkey)
    msg = read_file(fich)
    tag = compute_prefix_mac(key, msg)
    write_file(fich + ".mac", tag)


def do_ver(fich, fkey):
    key = read_file(fkey)
    msg = read_file(fich)
    stored_tag = read_file(fich + ".mac")
    computed_tag = compute_prefix_mac(key, msg)

    # comparação segura
    print(hmac.compare_digest(stored_tag, computed_tag))


def main():
    if len(sys.argv) < 3:
        usage()

    op = sys.argv[1]

    if op == "setup":
        if len(sys.argv) != 3:
            usage()
        do_setup(sys.argv[2])

    elif op == "mac":
        if len(sys.argv) != 4:
            usage()
        do_mac(sys.argv[2], sys.argv[3])

    elif op == "ver":
        if len(sys.argv) != 4:
            usage()
        do_ver(sys.argv[2], sys.argv[3])

    else:
        usage()


if __name__ == "__main__":
    main()