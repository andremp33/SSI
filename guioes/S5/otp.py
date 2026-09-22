import sys
from collections import Counter

def preproc(s: str) -> str:
    return "".join(c.upper() for c in s if c.isalpha())

def shift_char(c: str, k: int) -> str:
    base = ord('A')
    return chr(base + ((ord(c) - base + k) % 26))

def vigenere_dec(ct: str, key_shifts):
    out = []
    m = len(key_shifts)
    for i, c in enumerate(ct):
        out.append(shift_char(c, -key_shifts[i % m]))
    return "".join(out)

def main():
    if len(sys.argv) < 4:
        print("Uso: python3 vigenere_attack.py <TAM_CHAVE> <CRIPT> <PALAVRA1> [PALAVRA2 ...]")
        sys.exit(1)

    m = int(sys.argv[1])
    ct = preproc(sys.argv[2])
    words = [preproc(w) for w in sys.argv[3:]]

    if m <= 0:
        sys.exit(1)

    # fatias
    slices = [ct[i::m] for i in range(m)]
    common_pt = ['A', 'E', 'O', 'S']  # sugestão do guião

    # para cada fatia, gerar candidatos de shift (pequeno conjunto)
    candidates_per_pos = []
    for sl in slices:
        if not sl:
            candidates_per_pos.append([0])
            continue
        freq = Counter(sl).most_common(1)[0][0]  # letra mais frequente no criptograma da fatia
        cand = []
        for tgt in common_pt:
            # se freq = (tgt + k) => k = freq - tgt
            k = (ord(freq) - ord(tgt)) % 26
            if k not in cand:
                cand.append(k)
        candidates_per_pos.append(cand)

    # backtracking simples (m pequeno normalmente)
    key = [0] * m

    def dfs(i):
        if i == m:
            pt = vigenere_dec(ct, key)
            if any(w in pt for w in words):
                print("".join(chr(ord('A') + k) for k in key))
                print(pt)
                return True
            return False
        for k in candidates_per_pos[i]:
            key[i] = k
            if dfs(i + 1):
                return True
        return False

    dfs(0)
    # se falhar: resposta vazia

if __name__ == "__main__":
    main()