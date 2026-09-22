"""
Gestão local de chaves e estado criptográfico do cliente.

As chaves privadas permanecem no cliente; apenas chaves públicas são
exportadas para registo no servidor. O estado de sessões, rekey e
reply prekeys é local e oferece forward secrecy intermédia, não um
Double Ratchet completo.
"""

import json
import tempfile
from base64 import b64decode, b64encode
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from common.constants import CLIENT_KEYS_DIR, CLIENT_SESSION_DIR
from common.crypto_utils import (
    CryptoError,
    generate_ed25519_keypair,
    generate_x25519_keypair,
    load_private_key_from_pem,
    load_x25519_private_key_from_pem,
    serialize_private_key_to_pem,
    serialize_public_key_to_base64,
    serialize_x25519_private_key_to_pem,
    serialize_x25519_public_key_to_base64,
    sign_bytes,
)
from common.file_security import restrict_permissions, secure_mkdir
from common.validation import normalize_username


@dataclass
class IdentityBundle:
    ed25519_public_key: str
    x25519_public_key: str
    created_ed25519: bool = False
    created_x25519: bool = False

    @property
    def created_any(self) -> bool:
        return self.created_ed25519 or self.created_x25519


class KeyManager:
    """Gere identidade local e estado criptográfico persistido no cliente."""

    def __init__(
        self,
        keys_dir: Path = CLIENT_KEYS_DIR,
        session_dir: Path = CLIENT_SESSION_DIR,
    ):
        self.keys_dir = Path(keys_dir)
        secure_mkdir(self.keys_dir)
        self.session_dir = Path(session_dir)
        secure_mkdir(self.session_dir)

    def ensure_registration_identity(self, username: str) -> IdentityBundle:
        ed25519_public_key, created_ed25519 = self._ensure_ed25519_identity(username)
        try:
            x25519_public_key, created_x25519 = self._ensure_x25519_identity(username)
        except CryptoError:
            if created_ed25519:
                self.delete_identity(
                    username,
                    remove_ed25519=True,
                    remove_x25519=False,
                )
            raise
        return IdentityBundle(
            ed25519_public_key=ed25519_public_key,
            x25519_public_key=x25519_public_key,
            created_ed25519=created_ed25519,
            created_x25519=created_x25519,
        )

    def ensure_login_identity(self, username: str) -> IdentityBundle:
        ed25519_public_key = self.get_ed25519_public_key(username)
        x25519_public_key, created_x25519 = self._ensure_x25519_identity(username)
        return IdentityBundle(
            ed25519_public_key=ed25519_public_key,
            x25519_public_key=x25519_public_key,
            created_x25519=created_x25519,
        )

    def sign_login_challenge(self, username: str, challenge: bytes) -> bytes:
        private_key = self.load_ed25519_private_key(username)
        return sign_bytes(private_key, challenge)

    def sign_message(self, username: str, message: bytes) -> bytes:
        private_key = self.load_ed25519_private_key(username)
        return sign_bytes(private_key, message)

    def get_ed25519_public_key(self, username: str) -> str:
        private_key = self.load_ed25519_private_key(username)
        return serialize_public_key_to_base64(private_key.public_key())

    def get_x25519_public_key(self, username: str) -> str:
        private_key = self.load_x25519_private_key(username)
        return serialize_x25519_public_key_to_base64(private_key.public_key())

    def load_ed25519_private_key(self, username: str):
        return self._load_private_key(
            self._ed25519_private_key_path(username),
            load_private_key_from_pem,
            "Nao existe chave privada Ed25519 local para esse utilizador. Faca /register primeiro.",
            "Nao foi possivel ler a chave privada Ed25519 local.",
        )

    def load_x25519_private_key(self, username: str):
        return self._load_private_key(
            self._x25519_private_key_path(username),
            load_x25519_private_key_from_pem,
            "Nao existe chave privada X25519 local para esse utilizador.",
            "Nao foi possivel ler a chave privada X25519 local.",
        )

    def delete_identity(
        self,
        username: str,
        *,
        remove_ed25519: bool = True,
        remove_x25519: bool = True,
    ) -> None:
        if remove_ed25519:
            self._delete_key_file(
                self._ed25519_private_key_path(username),
                "Nao foi possivel remover a chave privada Ed25519 local temporaria.",
            )
        if remove_x25519:
            self._delete_key_file(
                self._x25519_private_key_path(username),
                "Nao foi possivel remover a chave privada X25519 local temporaria.",
            )

    def load_session_store(self, username: str) -> dict[str, Any]:
        store_path = self._session_store_path(username)
        if not store_path.exists():
            return self._default_session_store()
        restrict_permissions(store_path, 0o600)

        try:
            raw_store = json.loads(store_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return self._default_session_store()

        if not isinstance(raw_store, dict):
            return self._default_session_store()

        return self._normalize_session_store(raw_store)

    def save_session_store(self, username: str, store: dict[str, Any]) -> None:
        normalized_store = self._normalize_session_store(store)
        serialized = json.dumps(normalized_store, ensure_ascii=False, indent=2)
        self._write_text_atomically(
            self._session_store_path(username),
            serialized,
            "Nao foi possivel guardar o estado local das sessoes.",
        )

    def reset_session_store(self, username: str) -> None:
        store_path = self._session_store_path(username)
        if not store_path.exists():
            return
        self._delete_key_file(
            store_path,
            "Nao foi possivel remover o estado local das sessoes.",
        )

    def _ensure_ed25519_identity(self, username: str) -> tuple[str, bool]:
        key_path = self._ed25519_private_key_path(username)
        if key_path.exists():
            restrict_permissions(key_path, 0o600)
            return self.get_ed25519_public_key(username), False

        private_key, public_key = generate_ed25519_keypair()
        self._write_private_key_bytes(key_path, serialize_private_key_to_pem(private_key))
        return serialize_public_key_to_base64(public_key), True

    def _ensure_x25519_identity(self, username: str) -> tuple[str, bool]:
        key_path = self._x25519_private_key_path(username)
        if key_path.exists():
            restrict_permissions(key_path, 0o600)
            return self.get_x25519_public_key(username), False

        private_key, public_key = generate_x25519_keypair()
        self._write_private_key_bytes(
            key_path,
            serialize_x25519_private_key_to_pem(private_key),
        )
        return serialize_x25519_public_key_to_base64(public_key), True

    def _write_private_key_bytes(self, target_path: Path, private_pem: bytes) -> None:
        if target_path.exists():
            raise CryptoError("Ja existe uma chave privada local para esse utilizador.")

        temp_file = None
        try:
            with tempfile.NamedTemporaryFile(
                "wb",
                dir=self.keys_dir,
                delete=False,
            ) as file:
                file.write(private_pem)
                temp_file = Path(file.name)
            restrict_permissions(temp_file, 0o600)
            temp_file.replace(target_path)
            restrict_permissions(target_path, 0o600)
        finally:
            if temp_file is not None and temp_file.exists():
                temp_file.unlink()

    def _write_text_atomically(
        self,
        target_path: Path,
        content: str,
        error_message: str,
    ) -> None:
        temp_file = None
        try:
            with tempfile.NamedTemporaryFile(
                "w",
                dir=target_path.parent,
                encoding="utf-8",
                delete=False,
            ) as file:
                file.write(content)
                temp_file = Path(file.name)
            restrict_permissions(temp_file, 0o600)
            temp_file.replace(target_path)
            restrict_permissions(target_path, 0o600)
        except OSError as exc:
            raise CryptoError(error_message) from exc
        finally:
            if temp_file is not None and temp_file.exists():
                temp_file.unlink()

    @staticmethod
    def _load_private_key(
        key_path: Path,
        loader,
        missing_message: str,
        read_error_message: str,
    ):
        if not key_path.exists():
            raise CryptoError(missing_message)
        restrict_permissions(key_path, 0o600)

        try:
            pem_data = key_path.read_bytes()
        except OSError as exc:
            raise CryptoError(read_error_message) from exc

        return loader(pem_data)

    @staticmethod
    def _delete_key_file(key_path: Path, error_message: str) -> None:
        if not key_path.exists():
            return

        try:
            key_path.unlink()
        except OSError as exc:
            raise CryptoError(error_message) from exc

    def _ed25519_private_key_path(self, username: str) -> Path:
        return self.keys_dir / f"{self._username_path_component(username)}_ed25519_private.pem"

    def _x25519_private_key_path(self, username: str) -> Path:
        return self.keys_dir / f"{self._username_path_component(username)}_x25519_private.pem"

    def _session_store_path(self, username: str) -> Path:
        return self.session_dir / f"{self._username_path_component(username)}_sessions.json"

    @staticmethod
    def _username_path_component(username: str) -> str:
        safe_username = normalize_username(username)
        if not safe_username:
            raise CryptoError("Username local invalido para aceder a ficheiros sensiveis.")
        return safe_username

    @staticmethod
    def _safe_username(username: str) -> str:
        return normalize_username(username)

    @staticmethod
    def _encode_bytes(value: bytes) -> str:
        return b64encode(value).decode("ascii")

    @staticmethod
    def _decode_bytes(value: Any) -> str:
        if not isinstance(value, str):
            return ""
        try:
            b64decode(value.encode("ascii"), validate=True)
        except (ValueError, UnicodeEncodeError):
            return ""
        return value

    def _normalize_session_store(self, store: dict[str, Any]) -> dict[str, Any]:
        outbound_sessions = store.get("outbound_sessions", {})
        inbound_sessions = store.get("inbound_sessions", {})
        advertised_reply_prekeys = store.get("advertised_reply_prekeys", {})
        peer_reply_prekeys = store.get("peer_reply_prekeys", {})

        normalized_store = self._default_session_store()

        if isinstance(outbound_sessions, dict):
            for peer, record in outbound_sessions.items():
                safe_peer = self._safe_username(peer)
                normalized_record = self._normalize_outbound_session(record)
                if safe_peer and normalized_record is not None:
                    normalized_store["outbound_sessions"][safe_peer] = normalized_record

        if isinstance(inbound_sessions, dict):
            for peer, peer_sessions in inbound_sessions.items():
                safe_peer = self._safe_username(peer)
                if not safe_peer or not isinstance(peer_sessions, dict):
                    continue
                normalized_peer_sessions: dict[str, Any] = {}
                for session_id, record in peer_sessions.items():
                    normalized_record = self._normalize_inbound_session(record)
                    if isinstance(session_id, str) and session_id and normalized_record is not None:
                        normalized_peer_sessions[session_id] = normalized_record
                if normalized_peer_sessions:
                    normalized_store["inbound_sessions"][safe_peer] = normalized_peer_sessions

        if isinstance(advertised_reply_prekeys, dict):
            for prekey_id, record in advertised_reply_prekeys.items():
                normalized_record = self._normalize_reply_prekey_record(record)
                if isinstance(prekey_id, str) and prekey_id and normalized_record is not None:
                    normalized_store["advertised_reply_prekeys"][prekey_id] = normalized_record

        if isinstance(peer_reply_prekeys, dict):
            for peer, record in peer_reply_prekeys.items():
                safe_peer = self._safe_username(peer)
                normalized_record = self._normalize_peer_reply_prekey(record)
                if safe_peer and normalized_record is not None:
                    normalized_store["peer_reply_prekeys"][safe_peer] = normalized_record

        return normalized_store

    def _normalize_outbound_session(self, record: Any) -> dict[str, Any] | None:
        if not isinstance(record, dict):
            return None

        session_id = record.get("session_id")
        chain_key = self._decode_bytes(record.get("chain_key"))
        session_public_key = self._normalize_text(record.get("session_public_key"))
        if not isinstance(session_id, str) or not session_id or not chain_key or not session_public_key:
            return None

        return {
            "session_id": session_id,
            "chain_key": chain_key,
            "next_counter": self._normalize_int(record.get("next_counter")),
            "created_at": self._normalize_text(record.get("created_at")),
            "expires_at": self._normalize_text(record.get("expires_at")),
            "init_mode": self._normalize_text(record.get("init_mode")),
            "session_public_key": session_public_key,
            "peer_reply_prekey_id": self._normalize_text(record.get("peer_reply_prekey_id")),
        }

    def _normalize_inbound_session(self, record: Any) -> dict[str, Any] | None:
        if not isinstance(record, dict):
            return None

        chain_key = self._decode_bytes(record.get("chain_key"))
        if not chain_key:
            return None

        return {
            "chain_key": chain_key,
            "next_counter": self._normalize_int(record.get("next_counter")),
            "created_at": self._normalize_text(record.get("created_at")),
            "expires_at": self._normalize_text(record.get("expires_at")),
        }

    def _normalize_reply_prekey_record(self, record: Any) -> dict[str, Any] | None:
        if not isinstance(record, dict):
            return None

        private_key_pem_b64 = self._decode_bytes(record.get("private_key_pem_b64"))
        public_key = self._normalize_text(record.get("public_key"))
        peer = self._safe_username(record.get("peer", ""))
        if not private_key_pem_b64 or not public_key or not peer:
            return None

        return {
            "peer": peer,
            "public_key": public_key,
            "private_key_pem_b64": private_key_pem_b64,
            "created_at": self._normalize_text(record.get("created_at")),
        }

    def _normalize_peer_reply_prekey(self, record: Any) -> dict[str, Any] | None:
        if not isinstance(record, dict):
            return None

        prekey_id = self._normalize_text(record.get("prekey_id"))
        public_key = self._normalize_text(record.get("public_key"))
        if not prekey_id or not public_key:
            return None

        return {
            "prekey_id": prekey_id,
            "public_key": public_key,
            "received_at": self._normalize_text(record.get("received_at")),
        }

    @staticmethod
    def _default_session_store() -> dict[str, Any]:
        return {
            "version": 1,
            "outbound_sessions": {},
            "inbound_sessions": {},
            "advertised_reply_prekeys": {},
            "peer_reply_prekeys": {},
        }

    @staticmethod
    def _normalize_int(value: Any) -> int:
        if isinstance(value, bool):
            return 0
        if isinstance(value, int) and value >= 0:
            return value
        return 0

    @staticmethod
    def _normalize_text(value: Any) -> str:
        if not isinstance(value, str):
            return ""
        return value.strip()
