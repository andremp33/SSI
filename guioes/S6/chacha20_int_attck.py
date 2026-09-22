import sys


NONCE_SIZE = 16


def read_file(path):
    with open(path, "rb") as f:
        return f.read()


def write_file(path, data):
    with open(path, "wb") as f:
        f.write(data)


def main():
    if len(sys.argv) != 5:
        print("Uso: python3 chacha20_int_attck.py <fctxt> <pos> <ptxtAtPos> <newPtxtAtPos>")
        sys.exit(1)

    fctxt = sys.argv[1]
    pos = int(sys.argv[2])
    ptxt_at_pos = sys.argv[3].encode()
    new_ptxt_at_pos = sys.argv[4].encode()

    if len(ptxt_at_pos) != len(new_ptxt_at_pos):
        print("Erro: <ptxtAtPos> e <newPtxtAtPos> devem ter o mesmo tamanho.")
        sys.exit(1)

    data = bytearray(read_file(fctxt))

    #nonce || ciphertext
    
    ctxt_start = NONCE_SIZE
    attack_start = ctxt_start + pos
    attack_end = attack_start + len(ptxt_at_pos)

    if attack_end > len(data):
        print("Erro: posição/fragmento fora dos limites do criptograma.")
        sys.exit(1)

    for i in range(len(ptxt_at_pos)):
        old_c = data[attack_start + i]
        old_p = ptxt_at_pos[i]
        new_p = new_ptxt_at_pos[i]

        # new_c = old_c ^ old_p ^ new_p
        data[attack_start + i] = old_c ^ old_p ^ new_p

    write_file(fctxt + ".attck", data)


if __name__ == "__main__":
    main()