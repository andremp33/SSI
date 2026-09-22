"""
Persistência de utilizadores do servidor.

Guarda usernames, contactos e public keys usadas pelo protocolo.
Não guarda passwords nem chaves privadas dos utilizadores.
"""

import json
import os
import tempfile
import threading
from pathlib import Path
from typing import Any

from common.file_security import restrict_permissions, secure_mkdir
from common.validation import clean_string, normalize_username


class UserDatabase:
    """Base de dados JSON para utilizadores e contactos."""

    def __init__(self, file_path: Path):
        self.file_path = Path(file_path)
        secure_mkdir(self.file_path.parent)
        restrict_permissions(self.file_path, 0o600)
        self._lock = threading.RLock()
        self._data = self._load()

    def register_user(
        self,
        username: str,
        *,
        ed25519_public_key: str,
        x25519_public_key: str,
    ) -> bool:
        username = normalize_username(username)
        if not username:
            return False
        with self._lock:
            if username in self._data["users"]:
                return False

            self._data["users"][username] = {
                "username": username,
                "contacts": [],
                "security": self._default_security_profile(
                    ed25519_public_key=ed25519_public_key,
                    x25519_public_key=x25519_public_key,
                ),
            }
            self._save_locked()
            return True

    def user_exists(self, username: str) -> bool:
        username = normalize_username(username)
        if not username:
            return False
        with self._lock:
            return username in self._data["users"]

    def add_contact(self, owner_username: str, contact_username: str) -> tuple[bool, str]:
        owner_username = normalize_username(owner_username)
        contact_username = normalize_username(contact_username)
        with self._lock:
            if owner_username not in self._data["users"]:
                return False, "O utilizador autenticado não existe."

            if contact_username not in self._data["users"]:
                return False, "O utilizador de destino não existe."

            if owner_username == contact_username:
                return False, "Não pode adicionar o próprio utilizador como contacto."

            contacts = self._data["users"][owner_username]["contacts"]
            if contact_username in contacts:
                return False, "Esse utilizador já está na lista de contactos."

            contacts.append(contact_username)
            contacts.sort()
            self._save_locked()
            return True, "Contacto adicionado com sucesso."

    def list_contacts(self, username: str) -> list[str]:
        username = normalize_username(username)
        if not username:
            return []
        with self._lock:
            if username not in self._data["users"]:
                return []
            return list(self._data["users"][username]["contacts"])

    def list_users(self) -> list[str]:
        with self._lock:
            return sorted(self._data["users"].keys())

    def get_user_record(self, username: str) -> dict | None:
        username = normalize_username(username)
        if not username:
            return None
        with self._lock:
            user_record = self._data["users"].get(username)
            if not isinstance(user_record, dict):
                return None
            return {
                "username": user_record.get("username", username),
                "contacts": list(user_record.get("contacts", [])),
                "security": dict(user_record.get("security", {})),
            }

    def get_public_keys(self, username: str) -> dict[str, str] | None:
        username = normalize_username(username)
        if not username:
            return None
        with self._lock:
            public_keys = self._extract_public_keys(self._data["users"].get(username))
            if public_keys is None:
                return None
            return dict(public_keys)

    def get_ed25519_public_key(self, username: str) -> str | None:
        public_keys = self.get_public_keys(username)
        if public_keys is None:
            return None
        return public_keys.get("ed25519")

    def ensure_user_public_keys(
        self,
        username: str,
        *,
        ed25519_public_key: str | None = None,
        x25519_public_key: str | None = None,
    ) -> tuple[bool, str]:
        username = normalize_username(username)
        if not username:
            return False, "O username autenticado e invalido."
        with self._lock:
            user_record = self._data["users"].get(username)
            if not isinstance(user_record, dict):
                return False, "O utilizador autenticado não existe."

            security = user_record.setdefault("security", {})
            if not isinstance(security, dict):
                security = {}
                user_record["security"] = security

            public_keys = security.setdefault("public_keys", {})
            if not isinstance(public_keys, dict):
                public_keys = {}
                security["public_keys"] = public_keys

            changed = False
            for key_name, received_value in (
                ("ed25519", self._clean_string(ed25519_public_key)),
                ("x25519", self._clean_string(x25519_public_key)),
            ):
                if not received_value:
                    continue

                stored_value = self._clean_string(public_keys.get(key_name))
                if stored_value and stored_value != received_value:
                    return (
                        False,
                        f"A chave publica {key_name.upper()} nao coincide com a registada.",
                    )

                if not stored_value:
                    public_keys[key_name] = received_value
                    changed = True

            if changed:
                self._save_locked()

            return True, "Chaves publicas sincronizadas."

    def _load(self) -> dict:
        if not self.file_path.exists():
            return {"users": {}}

        try:
            with self.file_path.open("r", encoding="utf-8") as file:
                data = json.load(file)
        except (json.JSONDecodeError, OSError):
            return {"users": {}}

        users = data.get("users")
        if not isinstance(users, dict):
            return {"users": {}}

        normalized_users = {}
        for username, info in users.items():
            safe_username = normalize_username(username)
            if not safe_username:
                continue

            contacts = info.get("contacts", []) if isinstance(info, dict) else []
            if not isinstance(contacts, list):
                contacts = []

            security = info.get("security", {}) if isinstance(info, dict) else {}
            if not isinstance(security, dict):
                security = {}

            public_keys = security.get("public_keys", {})
            authentication = security.get("authentication", {})
            if not isinstance(public_keys, dict):
                public_keys = {}
            if not isinstance(authentication, dict):
                authentication = {}

            normalized_users[safe_username] = {
                "username": safe_username,
                "contacts": sorted(
                    contact
                    for contact in (normalize_username(contact) for contact in contacts)
                    if contact
                ),
                "security": {
                    "public_keys": self._normalize_public_keys(public_keys),
                    "authentication": dict(authentication),
                },
            }

        return {"users": normalized_users}

    @classmethod
    def _extract_public_keys(cls, user_record: Any) -> dict[str, str] | None:
        if not isinstance(user_record, dict):
            return None

        security = user_record.get("security", {})
        if not isinstance(security, dict):
            return None

        public_keys = security.get("public_keys", {})
        if not isinstance(public_keys, dict):
            return None

        normalized_public_keys = cls._normalize_public_keys(public_keys)
        return normalized_public_keys or None

    @classmethod
    def _normalize_public_keys(cls, public_keys: dict[str, Any]) -> dict[str, str]:
        normalized: dict[str, str] = {}
        for key_name in ("ed25519", "x25519"):
            value = cls._clean_string(public_keys.get(key_name))
            if value:
                normalized[key_name] = value
        return normalized

    @staticmethod
    def _default_security_profile(
        *,
        ed25519_public_key: str,
        x25519_public_key: str,
    ) -> dict:
        return {
            "public_keys": {
                "ed25519": ed25519_public_key,
                "x25519": x25519_public_key,
            },
            "authentication": {},
        }

    @staticmethod
    def _clean_string(value: Any) -> str:
        return clean_string(value)

    def _save_locked(self) -> None:
        temp_file = None
        try:
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                dir=self.file_path.parent,
                delete=False,
            ) as file:
                json.dump(self._data, file, ensure_ascii=False, indent=2)
                temp_file = file.name
            restrict_permissions(Path(temp_file), 0o600)
            os.replace(temp_file, self.file_path)
        finally:
            if temp_file and os.path.exists(temp_file):
                os.unlink(temp_file)
