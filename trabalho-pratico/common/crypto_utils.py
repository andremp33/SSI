"""
Funções criptográficas comuns ao cliente e ao servidor.

Ed25519 é usado para assinaturas, X25519 para acordo de chaves,
HKDF-SHA256 para derivação e ChaCha20-Poly1305 como AEAD.
Base64 é usado apenas para transportar bytes em mensagens JSON.
"""

import base64
import json

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class CryptoError(Exception):
    """Erro associado a material ou operações criptográficas."""


def generate_ed25519_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def generate_x25519_keypair() -> tuple[X25519PrivateKey, X25519PublicKey]:
    private_key = X25519PrivateKey.generate()
    return private_key, private_key.public_key()


def serialize_private_key_to_pem(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def serialize_x25519_private_key_to_pem(private_key: X25519PrivateKey) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def load_private_key_from_pem(pem_data: bytes) -> Ed25519PrivateKey:
    try:
        private_key = serialization.load_pem_private_key(pem_data, password=None)
    except (TypeError, ValueError) as exc:
        raise CryptoError("A chave privada local está inválida.") from exc

    if not isinstance(private_key, Ed25519PrivateKey):
        raise CryptoError("A chave privada local não é Ed25519.")
    return private_key


def load_x25519_private_key_from_pem(pem_data: bytes) -> X25519PrivateKey:
    try:
        private_key = serialization.load_pem_private_key(pem_data, password=None)
    except (TypeError, ValueError) as exc:
        raise CryptoError("A chave privada X25519 local está inválida.") from exc

    if not isinstance(private_key, X25519PrivateKey):
        raise CryptoError("A chave privada local não é X25519.")
    return private_key


def serialize_public_key_to_base64(public_key: Ed25519PublicKey) -> str:
    raw_key = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return encode_bytes_to_base64(raw_key)


def serialize_x25519_public_key_to_base64(public_key: X25519PublicKey) -> str:
    raw_key = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return encode_bytes_to_base64(raw_key)


def load_public_key_from_base64(encoded_key: str) -> Ed25519PublicKey:
    raw_key = _decode_fixed_size_base64(
        encoded_key,
        expected_size=32,
        invalid_message="A public key Ed25519 registada é inválida.",
        invalid_base64_message="A public key Ed25519 registada não está em base64 válido.",
        invalid_size_message="A public key Ed25519 tem tamanho inválido.",
    )

    try:
        return Ed25519PublicKey.from_public_bytes(raw_key)
    except ValueError as exc:
        raise CryptoError("A public key Ed25519 registada não é válida.") from exc


def load_x25519_public_key_from_base64(encoded_key: str) -> X25519PublicKey:
    raw_key = _decode_fixed_size_base64(
        encoded_key,
        expected_size=32,
        invalid_message="A public key X25519 registada é inválida.",
        invalid_base64_message="A public key X25519 registada não está em base64 válido.",
        invalid_size_message="A public key X25519 tem tamanho inválido.",
    )

    try:
        return X25519PublicKey.from_public_bytes(raw_key)
    except ValueError as exc:
        raise CryptoError("A public key X25519 registada não é válida.") from exc


def encode_bytes_to_base64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def decode_base64_to_bytes(encoded_data: str) -> bytes:
    if not isinstance(encoded_data, str) or not encoded_data.strip():
        raise CryptoError("Os dados em base64 são inválidos.")

    try:
        return base64.b64decode(encoded_data.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise CryptoError("Os dados em base64 são inválidos.") from exc


def sign_bytes(private_key: Ed25519PrivateKey, data: bytes) -> bytes:
    return private_key.sign(data)


def verify_signature(public_key: Ed25519PublicKey, data: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, data)
    except InvalidSignature:
        return False
    return True


def derive_x25519_shared_key(
    private_key: X25519PrivateKey,
    peer_public_key: X25519PublicKey,
    *,
    info: bytes,
) -> bytes:
    if not isinstance(info, bytes) or not info:
        raise CryptoError("O contexto HKDF da mensagem é inválido.")

    try:
        shared_secret = private_key.exchange(peer_public_key)
    except ValueError as exc:
        raise CryptoError("Falhou o acordo de chaves X25519.") from exc

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    )
    return hkdf.derive(shared_secret)


def derive_hkdf_key(
    key_material: bytes,
    *,
    info: bytes,
    salt: bytes | None = None,
    length: int = 32,
) -> bytes:
    if not isinstance(key_material, bytes) or not key_material:
        raise CryptoError("O material base de derivacao HKDF e invalido.")
    if not isinstance(info, bytes) or not info:
        raise CryptoError("O contexto HKDF da derivacao e invalido.")
    if salt is not None and not isinstance(salt, bytes):
        raise CryptoError("O salt HKDF da derivacao e invalido.")
    if not isinstance(length, int) or length <= 0:
        raise CryptoError("O tamanho de derivacao HKDF e invalido.")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(key_material)


def encrypt_chacha20_poly1305(
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    aad: bytes,
) -> bytes:
    _validate_chacha20_inputs(key, nonce)
    if not isinstance(plaintext, bytes):
        raise CryptoError("O plaintext a cifrar tem de estar em bytes.")
    if not isinstance(aad, bytes):
        raise CryptoError("Os dados autenticados adicionais têm de estar em bytes.")

    cipher = ChaCha20Poly1305(key)
    try:
        return cipher.encrypt(nonce, plaintext, aad)
    except Exception as exc:
        raise CryptoError("Falhou a cifragem da mensagem com ChaCha20-Poly1305.") from exc


def decrypt_chacha20_poly1305(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    aad: bytes,
) -> bytes:
    _validate_chacha20_inputs(key, nonce)
    if not isinstance(ciphertext, bytes):
        raise CryptoError("O ciphertext a decifrar tem de estar em bytes.")
    if not isinstance(aad, bytes):
        raise CryptoError("Os dados autenticados adicionais têm de estar em bytes.")

    cipher = ChaCha20Poly1305(key)
    try:
        return cipher.decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise CryptoError(
            "Falhou a validação de integridade da mensagem cifrada."
        ) from exc
    except Exception as exc:
        raise CryptoError("Falhou a decifragem da mensagem cifrada.") from exc


def canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise CryptoError("Não foi possível serializar os dados criptográficos.") from exc


def _decode_fixed_size_base64(
    encoded_key: str,
    *,
    expected_size: int,
    invalid_message: str,
    invalid_base64_message: str,
    invalid_size_message: str,
) -> bytes:
    if not isinstance(encoded_key, str) or not encoded_key.strip():
        raise CryptoError(invalid_message)

    try:
        raw_key = base64.b64decode(encoded_key.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise CryptoError(invalid_base64_message) from exc

    if len(raw_key) != expected_size:
        raise CryptoError(invalid_size_message)

    return raw_key


def _validate_chacha20_inputs(key: bytes, nonce: bytes) -> None:
    if not isinstance(key, bytes) or len(key) != 32:
        raise CryptoError("A chave ChaCha20-Poly1305 tem tamanho inválido.")
    if not isinstance(nonce, bytes) or len(nonce) != 12:
        raise CryptoError("O nonce ChaCha20-Poly1305 tem tamanho inválido.")
