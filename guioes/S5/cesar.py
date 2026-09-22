# cesar.py
import sys

def preproc(str):
    l = []
    for c in str:
        if c.isalpha():
          l.append(c.upper())
    return "".join(l)

def shift_char(c: str, k: int) -> str:
    base = ord('A')
    return chr(base + ((ord(c) - base + k) % 26))

def main():
    if len(sys.argv) != 4:
        print("Uso: python3 cesar.py enc|dec <CHAVE> <MENSAGEM>")
        sys.exit(1)

    op = sys.argv[1]
    key = sys.argv[2].upper()
    msg = preproc(sys.argv[3])

    if len(key) != 1 or not ('A' <= key <= 'Z'):
        print("Chave inválida (tem de ser uma letra A..Z)")
        sys.exit(1)

    k = ord(key) - ord('A')
    if op == "dec":
        k = -k
    elif op != "enc":
        print("Operação inválida (enc ou dec)")
        sys.exit(1)

    out = "".join(shift_char(c, k) for c in msg)
    print(out)

if __name__ == "__main__":
    main()