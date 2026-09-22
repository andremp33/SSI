# cesar_attack.py
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

def caesar_dec(ct: str, k: int) -> str:
    return "".join(shift_char(c, -k) for c in ct)

def main():
    if len(sys.argv) < 3:
        print("Uso: python3 cesar_attack.py <CRIPT> <PALAVRA1> [PALAVRA2 ...]")
        sys.exit(1)

    ct = preproc(sys.argv[1])
    words = [preproc(w) for w in sys.argv[2:]]

    for k in range(26):
        pt = caesar_dec(ct, k)
        if any(w in pt for w in words):
            key_letter = chr(ord('A') + k)
            print(key_letter)
            print(pt)
            return

    # se não encontrou, não imprime nada (resposta vazia)

if __name__ == "__main__":
    main()