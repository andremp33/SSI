import sys
import random

def bad_prng(n: int) -> bytes:
    random.seed(random.randbytes(2))
    return random.randbytes(n)

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def main():
    if len(sys.argv) != 4:
        print("Uso: python3 bad_otp.py setup|enc|dec <ARG2> <ARG3>")
        sys.exit(1)

    mode = sys.argv[1]

    if mode == "setup":
        n = int(sys.argv[2])
        keyfile = sys.argv[3]
        key = bad_prng(n)
        with open(keyfile, "wb") as f:
            f.write(key)
        return

    if mode in ("enc", "dec"):
        in_file = sys.argv[2]
        key_file = sys.argv[3]

        msg = open(in_file, "rb").read()
        key = open(key_file, "rb").read()

        if len(key) < len(msg):
            print("Erro: chave menor do que a mensagem/criptograma", file=sys.stderr)
            sys.exit(1)

        out = xor_bytes(msg, key[:len(msg)])

        if mode == "enc":
            open(in_file + ".enc", "wb").write(out)
            sys.stdout.buffer.write(out)
        else:
            open(in_file + ".dec", "wb").write(out)
            sys.stdout.buffer.write(out)
        return

    print("Modo inválido")
    sys.exit(1)

if __name__ == "__main__":
    main()