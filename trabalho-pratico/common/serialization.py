"""
Serialização JSON usada pelo protocolo aplicacional.

Converte mensagens entre dicionários Python e bytes UTF-8,
exigindo que o valor de topo recebido da rede seja um objeto JSON.
"""

import json
from typing import Any

from common.constants import ENCODING


class SerializationError(Exception):
    """Erro de codificação ou descodificação JSON."""


def encode_json(payload: dict[str, Any]) -> bytes:
    try:
        return json.dumps(payload, ensure_ascii=False).encode(ENCODING)
    except (TypeError, ValueError) as exc:
        raise SerializationError(f"Invalid JSON payload: {exc}") from exc


def decode_json(raw_data: bytes) -> dict[str, Any]:
    try:
        payload = json.loads(raw_data.decode(ENCODING))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SerializationError(f"Invalid JSON data: {exc}") from exc

    if not isinstance(payload, dict):
        raise SerializationError("Top-level JSON message must be an object.")

    return payload
