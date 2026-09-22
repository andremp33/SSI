from multiprocessing import Process, Pipe
from cryptography.hazmat.primitives.asymmetric import dh, padding
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, load_der_public_key
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509 import load_pem_x509_certificate
import os

# Parâmetros fixos p e g
p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
g = 2

pn = dh.DHParameterNumbers(p, g)
parameters = pn.parameters()

def mkpair(x, y):
    len_x = len(x)
    len_x_bytes = len_x.to_bytes(2, "little")
    return len_x_bytes + x + y

def unpair(xy):
    len_x = int.from_bytes(xy[:2], "little")
    x = xy[2 : len_x + 2]
    y = xy[len_x + 2 :]
    return x, y

def derive_key(shared_key):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'sts_aes_gcm'
    ).derive(shared_key)

def load_private_key(path):
    with open(path, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_cert(path):
    with open(path, 'rb') as f:
        return load_pem_x509_certificate(f.read())

def alice_process(conn):
    # Carregar chaves e certificados
    alice_private_rsa = load_private_key('Alice.key')
    alice_cert = load_cert('Alice.crt')
    ca_cert = load_cert('CA.crt')

    # Gerar chaves DH
    alice_dh_private = parameters.generate_private_key()
    alice_dh_public = alice_dh_private.public_key()
    gx = alice_dh_public.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    # 1. Alice → Bob: envia g^x
    conn.send(gx)

    # 2. Bob → Alice: recebe g^y, SigB(g^y, g^x), CertB
    data = conn.recv()
    gy, rest = unpair(data)
    sig_b, cert_b_bytes = unpair(rest)

    # Verificar certificado do Bob com CA
    bob_cert = load_pem_x509_certificate(cert_b_bytes)
    ca_public = ca_cert.public_key()
    ca_public.verify(
        bob_cert.signature,
        bob_cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        bob_cert.signature_hash_algorithm
    )
    print("Alice: certificado do Bob verificado com sucesso!")

    # Verificar assinatura do Bob: SigB(g^y, g^x)
    bob_public_rsa = bob_cert.public_key()
    bob_public_rsa.verify(
        sig_b,
        mkpair(gy, gx),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Alice: assinatura do Bob verificada com sucesso!")

    # 3. Alice → Bob: envia SigA(g^x, g^y), CertA
    sig_a = alice_private_rsa.sign(
        mkpair(gx, gy),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    cert_a_bytes = alice_cert.public_bytes(Encoding.PEM)
    conn.send(mkpair(sig_a, cert_a_bytes))

    # 4. Calcular segredo partilhado
    bob_dh_public = load_der_public_key(gy)
    K = alice_dh_private.exchange(bob_dh_public)
    aes_key = derive_key(K)
    print(f"Alice K (hex): {K.hex()[:32]}...")

    # Cifrar e enviar mensagem
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    mensagem = b"Ola Bob, mensagem autenticada da Alice!"
    ciphertext = aesgcm.encrypt(nonce, mensagem, None)
    conn.send(nonce + ciphertext)
    print(f"Alice enviou (cifrado): {ciphertext.hex()[:32]}...")

def bob_process(conn):
    # Carregar chaves e certificados
    bob_private_rsa = load_private_key('Bob.key')
    bob_cert = load_cert('Bob.crt')
    ca_cert = load_cert('CA.crt')

    # Gerar chaves DH
    bob_dh_private = parameters.generate_private_key()
    bob_dh_public = bob_dh_private.public_key()
    gy = bob_dh_public.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    # 1. Alice → Bob: recebe g^x
    gx = conn.recv()

    # Assinar SigB(g^y, g^x)
    sig_b = bob_private_rsa.sign(
        mkpair(gy, gx),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    cert_b_bytes = bob_cert.public_bytes(Encoding.PEM)

    # 2. Bob → Alice: envia g^y, SigB(g^y, g^x), CertB
    conn.send(mkpair(gy, mkpair(sig_b, cert_b_bytes)))

    # 3. Alice → Bob: recebe SigA(g^x, g^y), CertA
    data = conn.recv()
    sig_a, cert_a_bytes = unpair(data)

    # Verificar certificado da Alice com CA
    alice_cert = load_pem_x509_certificate(cert_a_bytes)
    ca_public = ca_cert.public_key()
    ca_public.verify(
        alice_cert.signature,
        alice_cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        alice_cert.signature_hash_algorithm
    )
    print("Bob: certificado da Alice verificado com sucesso!")

    # Verificar assinatura da Alice: SigA(g^x, g^y)
    alice_public_rsa = alice_cert.public_key()
    alice_public_rsa.verify(
        sig_a,
        mkpair(gx, gy),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Bob: assinatura da Alice verificada com sucesso!")

    # 4. Calcular segredo partilhado
    alice_dh_public = load_der_public_key(gx)
    K = bob_dh_private.exchange(alice_dh_public)
    aes_key = derive_key(K)
    print(f"Bob   K (hex): {K.hex()[:32]}...")

    # Receber e decifrar mensagem
    data = conn.recv()
    nonce = data[:12]
    ciphertext = data[12:]
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    print(f"Bob recebeu (decifrado): {plaintext.decode()}")

if __name__ == '__main__':
    parent_conn, child_conn = Pipe()
    p1 = Process(target=alice_process, args=(parent_conn,))
    p2 = Process(target=bob_process, args=(child_conn,))
    p1.start(); p2.start()
    p1.join(); p2.join()