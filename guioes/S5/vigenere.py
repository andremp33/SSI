# vigenere.py
import sys

def preproc(str):
    l = []
    for c in str:
        if c.isalpha():
          l.append(c.upper())
    return "".join(l)

def k_from_key(key: str):
    return [ord(c) - ord('A') for c in key]

def shift_char(c: str, k: int) -> str:
    base = ord('A')
    return chr(base + ((ord(c) - base + k) % 26))

def main():
    if len(sys.argv) != 4:
        print("Uso: python3 vigenere.py enc|dec <CHAVE> <MENSAGEM>")
        sys.exit(1)

    op = sys.argv[1]
    key = preproc(sys.argv[2])
    text = preproc(sys.argv[3])

    if not key:
        print("Chave inválida (tem de ter letras A..Z)")
        sys.exit(1)

    ks = k_from_key(key)
    out = []
    for i, c in enumerate(text):
        k = ks[i % len(ks)]
        if op == "dec":
            k = -k
        elif op != "enc":
            print("Operação inválida (enc ou dec)")
            sys.exit(1)
        out.append(shift_char(c, k))

    print("".join(out))

if __name__ == "__main__":
    main()