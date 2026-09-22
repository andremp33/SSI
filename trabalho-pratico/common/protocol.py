"""
Framing aplicacional comum ao cliente e ao servidor.

Define envio e receção de mensagens JSON com prefixo de tamanho,
incluindo limites defensivos para payloads recebidos da rede.
"""

import socket
import struct
from typing import Any

from common.constants import HEADER_SIZE, MAX_PAYLOAD_SIZE, RECV_CHUNK_SIZE
from common.serialization import SerializationError, decode_json, encode_json


class ProtocolError(Exception):
    """Erro de framing ou de formato de mensagem."""


class ConnectionClosedError(ProtocolError):
    """Erro usado quando o par remoto fecha a ligação."""


def send_message(sock: socket.socket, payload: dict[str, Any]) -> None:
    body = encode_json(payload)
    if len(body) > MAX_PAYLOAD_SIZE:
        raise ProtocolError("Payload too large.")

    header = struct.pack("!I", len(body))
    sock.sendall(header + body)


def receive_message(sock: socket.socket) -> dict[str, Any]:
    header = _recv_exact(sock, HEADER_SIZE)
    message_size = struct.unpack("!I", header)[0]

    if message_size <= 0:
        raise ProtocolError("Invalid payload size.")

    if message_size > MAX_PAYLOAD_SIZE:
        raise ProtocolError("Payload exceeds allowed size.")

    body = _recv_exact(sock, message_size)

    try:
        return decode_json(body)
    except SerializationError as exc:
        raise ProtocolError(str(exc)) from exc


def _recv_exact(sock: socket.socket, expected_size: int) -> bytes:
    chunks: list[bytes] = []
    bytes_left = expected_size

    while bytes_left > 0:
        chunk = sock.recv(min(RECV_CHUNK_SIZE, bytes_left))
        if not chunk:
            raise ConnectionClosedError("Connection closed by remote peer.")
        chunks.append(chunk)
        bytes_left -= len(chunk)

    return b"".join(chunks)
