"""
Validação defensiva de valores recebidos da rede.

Centraliza normalização de usernames, tokens e tamanhos JSON para
reduzir entradas ambíguas antes de chegarem à lógica aplicacional.
"""

import json
import re
from typing import Any

from common.constants import MAX_USERNAME_LENGTH


USERNAME_PATTERN = re.compile(rf"^[A-Za-z0-9][A-Za-z0-9_.-]{{0,{MAX_USERNAME_LENGTH - 1}}}$")
TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]+$")
HEX_PATTERN = re.compile(r"^[0-9a-fA-F]+$")


def clean_string(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip()


def normalize_username(value: Any) -> str:
    username = clean_string(value)
    if not USERNAME_PATTERN.fullmatch(username):
        return ""
    return username


def username_policy_message() -> str:
    return (
        f"O username deve ter 1 a {MAX_USERNAME_LENGTH} caracteres, comecar por "
        "letra ou numero, e usar apenas letras, numeros, '.', '_' ou '-'."
    )


def is_safe_token(value: Any, *, max_length: int) -> bool:
    if not isinstance(value, str):
        return False
    token = clean_string(value)
    return bool(token == value and token and len(token) <= max_length and TOKEN_PATTERN.fullmatch(token))


def is_hex_token(value: Any, *, length: int) -> bool:
    token = clean_string(value)
    return bool(len(token) == length and HEX_PATTERN.fullmatch(token))


def json_size_bytes(value: Any) -> int:
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return len(encoded)
