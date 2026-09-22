import sys
import binascii
import hashpumpy


def usage():
    print("Uso:")
    print("  python3 mac_sha256_attack.py <msg_original> <mac_hex> <extra> <key_len> <fout>")
    sys.exit(1)


def main():
    if len(sys.argv) != 6:
        usage()

    msg_original = sys.argv[1]
    mac_hex = sys.argv[2]
    extra = sys.argv[3]
    key_len = int(sys.argv[4])
    fout = sys.argv[5]

    new_mac, new_msg = hashpumpy.hashpump(mac_hex, msg_original, extra, key_len)

    if isinstance(new_msg, str):
        new_msg = new_msg.encode()

    with open(fout, "wb") as f:
        f.write(new_msg)

    with open(fout + ".mac", "wb") as f:
        f.write(bytes.fromhex(new_mac))

    print("Mensagem forjada guardada em:", fout)
    print("Novo MAC guardado em:", fout + ".mac")
    print("Novo MAC (hex):", new_mac)
    print("Mensagem forjada (hex):", binascii.hexlify(new_msg).decode())


if __name__ == "__main__":
    main()

