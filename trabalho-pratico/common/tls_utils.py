"""
Utilitários TLS para proteger o canal cliente-servidor.

O cliente usa TOFU com pinning local para validar a identidade do
servidor nas ligações seguintes. Esta solução não substitui uma PKI
completa.
"""

import hashlib
import ipaddress
import os
import socket
import ssl
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from common.file_security import restrict_permissions, secure_mkdir


class TLSError(Exception):
    """Erro na identidade, confiança ou handshake TLS."""


class ServerIdentityError(TLSError):
    """Erro quando a identidade TLS confiada do servidor é inválida."""


def create_server_ssl_context(cert_path: Path, key_path: Path) -> ssl.SSLContext:
    ensure_server_tls_identity(cert_path, key_path)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    except ssl.SSLError as exc:
        raise TLSError(
            "Falhou o carregamento do certificado/chave TLS do servidor."
        ) from exc
    return context


def connect_tls_socket(
    host: str,
    port: int,
    *,
    trusted_cert_path: Path,
    fingerprint_path: Path,
) -> tuple[ssl.SSLSocket, bool, str]:
    secure_mkdir(trusted_cert_path.parent)
    bootstrap_performed = _needs_trust_bootstrap(trusted_cert_path, fingerprint_path)
    # A primeira ligação cria confiança local; as seguintes validam o pin guardado.
    if bootstrap_performed:
        expected_fingerprint = _bootstrap_server_trust(
            host,
            port,
            trusted_cert_path=trusted_cert_path,
            fingerprint_path=fingerprint_path,
        )
    else:
        expected_fingerprint = load_stored_server_fingerprint(fingerprint_path)
        _load_pinned_server_certificate(trusted_cert_path)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED

    try:
        context.load_verify_locations(cafile=str(trusted_cert_path))
    except (OSError, ssl.SSLError) as exc:
        raise ServerIdentityError(
            "Falhou o carregamento do certificado TLS confiado do servidor."
        ) from exc

    try:
        raw_socket = socket.create_connection((host, port))
    except OSError as exc:
        raise TLSError(
            f"Nao foi possivel ligar ao servidor TLS em {host}:{port}."
        ) from exc

    try:
        tls_socket = context.wrap_socket(raw_socket, server_hostname=host)
    except ssl.SSLCertVerificationError as exc:
        raw_socket.close()
        raise ServerIdentityError(
            "A identidade TLS do servidor nao coincide com a confiada localmente."
        ) from exc
    except ssl.SSLError as exc:
        raw_socket.close()
        raise TLSError("Falhou o handshake TLS com o servidor.") from exc
    except Exception:
        raw_socket.close()
        raise

    presented_der_certificate = tls_socket.getpeercert(binary_form=True)
    if not presented_der_certificate:
        tls_socket.close()
        raise ServerIdentityError("O servidor nao apresentou um certificado TLS.")

    fingerprint = certificate_fingerprint_from_der(presented_der_certificate)
    if fingerprint != expected_fingerprint:
        tls_socket.close()
        raise ServerIdentityError(
            "A fingerprint TLS do servidor nao coincide com a guardada localmente."
        )

    return tls_socket, bootstrap_performed, fingerprint


def ensure_server_tls_identity(cert_path: Path, key_path: Path) -> None:
    secure_mkdir(cert_path.parent)

    cert_exists = cert_path.exists()
    key_exists = key_path.exists()
    if cert_exists and key_exists:
        restrict_permissions(key_path, 0o600)
        restrict_permissions(cert_path, 0o644)
        certificate = _load_pem_certificate(cert_path)
        private_key = _load_pem_private_key(key_path)
        _validate_certificate_matches_private_key(certificate, private_key)
        return

    if cert_exists != key_exists:
        raise TLSError(
            "A identidade TLS do servidor esta incompleta. "
            "Elimine os ficheiros TLS parciais ou reponha ambos."
        )

    _generate_server_tls_identity(cert_path, key_path)


def load_stored_server_fingerprint(fingerprint_path: Path) -> str:
    restrict_permissions(fingerprint_path, 0o600)
    try:
        stored_fingerprint = fingerprint_path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ServerIdentityError(
            "Nao foi possivel ler a fingerprint TLS confiada do servidor."
        ) from exc

    normalized = normalize_certificate_fingerprint(stored_fingerprint)
    if not normalized:
        raise ServerIdentityError(
            "A fingerprint TLS confiada do servidor esta vazia ou invalida."
        )
    return normalized


def certificate_fingerprint_from_der(certificate_der: bytes) -> str:
    digest = hashlib.sha256(certificate_der).hexdigest().upper()
    return ":".join(digest[index : index + 2] for index in range(0, len(digest), 2))


def normalize_certificate_fingerprint(value: str) -> str:
    cleaned = value.replace(":", "").strip().upper()
    if len(cleaned) != 64 or any(character not in "0123456789ABCDEF" for character in cleaned):
        return ""
    return ":".join(cleaned[index : index + 2] for index in range(0, len(cleaned), 2))


def _needs_trust_bootstrap(trusted_cert_path: Path, fingerprint_path: Path) -> bool:
    cert_exists = trusted_cert_path.exists()
    fingerprint_exists = fingerprint_path.exists()
    if not cert_exists and not fingerprint_exists:
        return True
    if cert_exists != fingerprint_exists:
        raise ServerIdentityError(
            "A confianca TLS local do servidor esta incompleta. "
            "Valide ou recrie os ficheiros em client/data/tls."
        )
    return False


def _bootstrap_server_trust(
    host: str,
    port: int,
    *,
    trusted_cert_path: Path,
    fingerprint_path: Path,
) -> str:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        raw_socket = socket.create_connection((host, port))
    except OSError as exc:
        raise TLSError(
            f"Nao foi possivel ligar ao servidor TLS em {host}:{port}."
        ) from exc

    try:
        tls_socket = context.wrap_socket(raw_socket, server_hostname=host)
    except ssl.SSLError as exc:
        raw_socket.close()
        raise TLSError("Falhou o handshake TLS inicial para TOFU.") from exc
    except Exception:
        raw_socket.close()
        raise

    try:
        certificate_der = tls_socket.getpeercert(binary_form=True)
        if not certificate_der:
            raise ServerIdentityError(
                "O servidor nao apresentou um certificado TLS durante o bootstrap TOFU."
            )
        x509.load_der_x509_certificate(certificate_der)
        certificate_pem = ssl.DER_cert_to_PEM_cert(certificate_der).encode("ascii")
        fingerprint = certificate_fingerprint_from_der(certificate_der)
    finally:
        tls_socket.close()

    try:
        _write_bytes_atomic(trusted_cert_path, certificate_pem)
        _write_text_atomic(fingerprint_path, f"{fingerprint}\n")
    except OSError as exc:
        try:
            trusted_cert_path.unlink(missing_ok=True)
        except OSError:
            pass
        try:
            fingerprint_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise ServerIdentityError(
            "Falhou a criacao da confianca TLS local do servidor em modo TOFU."
        ) from exc

    return fingerprint


def _generate_server_tls_identity(cert_path: Path, key_path: Path) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PT"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SSI Chat"),
            x509.NameAttribute(NameOID.COMMON_NAME, "ssi-chat-server"),
        ]
    )
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    x509.IPAddress(ipaddress.ip_address("::1")),
                ]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    certificate_pem = certificate.public_bytes(serialization.Encoding.PEM)

    try:
        _write_bytes_atomic(key_path, private_key_pem, permissions=0o600)
        _write_bytes_atomic(cert_path, certificate_pem, permissions=0o644)
    except OSError as exc:
        try:
            key_path.unlink(missing_ok=True)
        except OSError:
            pass
        try:
            cert_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise TLSError(
            "Falhou a geracao da identidade TLS persistente do servidor."
        ) from exc


def _load_pinned_server_certificate(cert_path: Path) -> x509.Certificate:
    restrict_permissions(cert_path, 0o600)
    return _load_pem_certificate(cert_path)


def _load_pem_certificate(cert_path: Path) -> x509.Certificate:
    try:
        certificate_pem = cert_path.read_bytes()
    except OSError as exc:
        raise TLSError(
            "Nao foi possivel ler o certificado TLS do servidor."
        ) from exc

    try:
        return x509.load_pem_x509_certificate(certificate_pem)
    except ValueError as exc:
        raise TLSError("O certificado TLS do servidor esta corrompido.") from exc


def _load_pem_private_key(key_path: Path):
    try:
        private_key_pem = key_path.read_bytes()
    except OSError as exc:
        raise TLSError(
            "Nao foi possivel ler a chave privada TLS do servidor."
        ) from exc

    try:
        return serialization.load_pem_private_key(private_key_pem, password=None)
    except (TypeError, ValueError) as exc:
        raise TLSError("A chave privada TLS do servidor esta corrompida.") from exc


def _validate_certificate_matches_private_key(certificate: x509.Certificate, private_key) -> None:
    certificate_public_key = certificate.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_key_public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if certificate_public_key != private_key_public:
        raise TLSError(
            "O certificado TLS do servidor nao corresponde a chave privada configurada."
        )


def _write_bytes_atomic(
    target_path: Path,
    data: bytes,
    *,
    permissions: int | None = None,
) -> None:
    temp_path = None
    secure_mkdir(target_path.parent)
    try:
        with tempfile.NamedTemporaryFile(
            "wb",
            dir=target_path.parent,
            delete=False,
        ) as file:
            file.write(data)
            temp_path = Path(file.name)
        if permissions is not None:
            os.chmod(temp_path, permissions)
        os.replace(temp_path, target_path)
    finally:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink()


def _write_text_atomic(target_path: Path, data: str) -> None:
    _write_bytes_atomic(target_path, data.encode("utf-8"), permissions=0o600)
