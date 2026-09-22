import sys
import random

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def main():
    if len(sys.argv) < 4:
        print("Uso: python3 bad_otp_attack.py <N> <FICHEIRO.enc> <PALAVRA1> [PALAVRA2 ...]")
        sys.exit(1)

    n = int(sys.argv[1])
    enc_file = sys.argv[2]
    words = [w.encode("utf-8") for w in sys.argv[3:]]

    ct = open(enc_file, "rb").read()

    for seed in range(1 << 16):
        r = random.Random()
        r.seed(seed.to_bytes(2, "big"))
        key = r.randbytes(n)

        pt = xor_bytes(ct, key[:len(ct)])

        if any(w in pt for w in words):
            try:
                sys.stdout.write(pt.decode("utf-8"))
            except UnicodeDecodeError:
                sys.stdout.buffer.write(pt)
            return

if __name__ == "__main__":
    main()