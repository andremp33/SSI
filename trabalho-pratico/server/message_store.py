"""
Persistência de mensagens offline do servidor.

As mensagens são guardadas por destinatário com estados pending/delivered.
O ack é idempotente e a escrita usa locks e substituição atómica para
reduzir o risco de corrupção do ficheiro JSON.
"""

import json
import os
import tempfile
import threading
import uuid
from copy import deepcopy
from pathlib import Path
from typing import Any

from common.constants import (
    DEFAULT_MESSAGE_CONTENT_TYPE,
    MESSAGE_ID_HEX_LENGTH,
    MESSAGE_STATUS_DELIVERED,
    MESSAGE_STATUS_PENDING,
)
from common.file_security import restrict_permissions, secure_mkdir
from common.validation import clean_string, is_hex_token, normalize_username


class MessageStore:
    """Armazém JSON de mensagens pendentes e entregues."""

    def __init__(self, file_path: Path):
        self.file_path = Path(file_path)
        secure_mkdir(self.file_path.parent)
        restrict_permissions(self.file_path, 0o600)
        self._lock = threading.RLock()
        self._data = self._load()

    def ensure_user(self, username: str) -> None:
        username = normalize_username(username)
        if not username:
            return
        with self._lock:
            created = username not in self._data["messages"]
            self._data["messages"].setdefault(username, [])
            if created:
                self._save_locked()

    def store_message(self, recipient: str, message: dict[str, Any]) -> dict[str, Any]:
        recipient = normalize_username(recipient)
        if not recipient:
            raise ValueError("Recipient username is invalid.")
        with self._lock:
            normalized_message = self._normalize_message_record(
                message,
                fallback_recipient=recipient,
            )
            self._data["messages"].setdefault(recipient, []).append(normalized_message)
            self._save_locked()
            return deepcopy(normalized_message)

    def get_pending_count(self, username: str) -> int:
        with self._lock:
            return sum(
                1
                for message in self._data["messages"].get(username, [])
                if message.get("status") == MESSAGE_STATUS_PENDING
            )

    def list_messages(
        self,
        username: str,
        *,
        statuses: set[str] | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        with self._lock:
            stored_messages = self._data["messages"].get(username, [])
            if statuses is None:
                messages = [deepcopy(message) for message in stored_messages]
                return messages[:limit] if limit is not None else messages

            messages = [
                deepcopy(message)
                for message in stored_messages
                if message.get("status") in statuses
            ]
            return messages[:limit] if limit is not None else messages

    def acknowledge_messages(
        self,
        username: str,
        message_ids: list[str],
        *,
        delivered_at: str | None = None,
    ) -> dict[str, list[str]]:
        result = {
            "acknowledged_ids": [],
            "already_delivered_ids": [],
            "unknown_ids": [],
        }
        unique_message_ids = self._deduplicate_message_ids(message_ids)
        if not unique_message_ids:
            return result

        with self._lock:
            stored_messages = self._data["messages"].get(username, [])
            indexed_messages = {
                message.get("message_id"): message
                for message in stored_messages
                if isinstance(message.get("message_id"), str)
            }

            modified = False
            for message_id in unique_message_ids:
                message = indexed_messages.get(message_id)
                if message is None:
                    result["unknown_ids"].append(message_id)
                    continue

                status = message.get("status")
                if status == MESSAGE_STATUS_PENDING:
                    message["status"] = MESSAGE_STATUS_DELIVERED
                    message["delivered_at"] = delivered_at
                    result["acknowledged_ids"].append(message_id)
                    modified = True
                    continue

                # Ack idempotente: repetir uma confirmação não altera a semântica.
                if status == MESSAGE_STATUS_DELIVERED:
                    if not self._clean_string(message.get("delivered_at")) and delivered_at:
                        message["delivered_at"] = delivered_at
                        modified = True
                    result["already_delivered_ids"].append(message_id)
                    continue

                message["status"] = MESSAGE_STATUS_DELIVERED
                message["delivered_at"] = delivered_at
                result["acknowledged_ids"].append(message_id)
                modified = True

            if modified:
                self._save_locked()

        return result

    def _load(self) -> dict:
        if not self.file_path.exists():
            return {"messages": {}}

        try:
            with self.file_path.open("r", encoding="utf-8") as file:
                data = json.load(file)
        except (json.JSONDecodeError, OSError):
            return {"messages": {}}

        messages = data.get("messages")
        if not isinstance(messages, dict):
            return {"messages": {}}

        normalized_messages: dict[str, list[dict[str, Any]]] = {}
        for username, stored_messages in messages.items():
            safe_username = normalize_username(username)
            if not safe_username or not isinstance(stored_messages, list):
                continue

            normalized_messages[safe_username] = []
            for message in stored_messages:
                if not isinstance(message, dict):
                    continue
                try:
                    normalized_messages[safe_username].append(
                        self._normalize_message_record(
                            message,
                            fallback_recipient=safe_username,
                        )
                    )
                except ValueError:
                    continue

        return {"messages": normalized_messages}

    def _normalize_message_record(
        self,
        message: dict[str, Any],
        *,
        fallback_recipient: str | None = None,
    ) -> dict[str, Any]:
        sender = normalize_username(message.get("sender"))
        recipient = normalize_username(message.get("recipient")) or normalize_username(
            fallback_recipient
        )
        timestamp = self._clean_string(message.get("timestamp"))
        if not sender or not recipient or not timestamp:
            raise ValueError("Message record is missing required fields.")

        payload = message.get("payload")
        if isinstance(payload, dict):
            normalized_payload = self._normalize_payload(payload)
        else:
            legacy_message = message.get("message")
            if not isinstance(legacy_message, str) or not legacy_message.strip():
                raise ValueError("Legacy message record is invalid.")
            normalized_payload = {
                "content_type": DEFAULT_MESSAGE_CONTENT_TYPE,
                "body": legacy_message.strip(),
            }

        metadata = message.get("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}

        status = self._clean_string(message.get("status")) or MESSAGE_STATUS_PENDING
        if status not in {MESSAGE_STATUS_PENDING, MESSAGE_STATUS_DELIVERED}:
            status = MESSAGE_STATUS_PENDING

        message_id = self._clean_string(message.get("message_id"))
        if not is_hex_token(message_id, length=MESSAGE_ID_HEX_LENGTH):
            message_id = uuid.uuid4().hex
        delivered_at = self._clean_string(message.get("delivered_at")) or None
        if status == MESSAGE_STATUS_PENDING:
            delivered_at = None

        return {
            "message_id": message_id,
            "sender": sender,
            "recipient": recipient,
            "payload": normalized_payload,
            "metadata": dict(metadata),
            "timestamp": timestamp,
            "status": status,
            "delivered_at": delivered_at,
        }

    def _normalize_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        content_type = self._clean_string(payload.get("content_type"))
        if not content_type:
            raise ValueError("Payload content_type is required.")

        if "body" not in payload:
            raise ValueError("Payload body is required.")

        body = payload.get("body")
        if isinstance(body, str):
            body = body.strip()
            if not body:
                raise ValueError("Payload body cannot be empty.")
        elif body is None:
            raise ValueError("Payload body cannot be null.")

        normalized_payload = {
            "content_type": content_type,
            "body": body,
        }

        for key, value in payload.items():
            if key not in {"content_type", "body"}:
                normalized_payload[key] = value

        return normalized_payload

    @staticmethod
    def _clean_string(value: Any) -> str:
        return clean_string(value)

    @classmethod
    def _deduplicate_message_ids(cls, message_ids: list[str]) -> list[str]:
        unique_message_ids: list[str] = []
        seen_ids: set[str] = set()
        for message_id in message_ids:
            cleaned_message_id = cls._clean_string(message_id)
            if (
                not is_hex_token(cleaned_message_id, length=MESSAGE_ID_HEX_LENGTH)
                or cleaned_message_id in seen_ids
            ):
                continue
            seen_ids.add(cleaned_message_id)
            unique_message_ids.append(cleaned_message_id)
        return unique_message_ids

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
