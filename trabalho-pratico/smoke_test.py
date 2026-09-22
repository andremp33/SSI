"""
Teste de fumo do fluxo principal do projeto.

Valida TLS, register/login, envio E2EE offline, inbox e ack. Este teste
não substitui uma suite completa de testes unitários ou de integração.
"""

import secrets
import socket
import tempfile
import threading
import time
from pathlib import Path

from client.client import ChatClient
from client.commands import ParsedCommand
from client.key_manager import KeyManager
from common.constants import (
    ACTION_INBOX,
    ACTION_LOGIN,
    ACTION_REGISTER,
    ACTION_SEND,
    DEFAULT_HOST,
    STATUS_OK,
)
from server import server as server_module


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="ssi-chat-smoke-") as temp_dir:
        root = Path(temp_dir)
        port = _free_port()
        _configure_runtime_paths(root)

        chat_server = server_module.ChatServer(host=DEFAULT_HOST, port=port)
        server_thread = threading.Thread(target=chat_server.start, daemon=True)
        server_thread.start()
        _wait_for_server_socket(chat_server)

        suffix = secrets.token_hex(4)
        alice = f"alice_{suffix}"
        bob = f"bob_{suffix}"

        registrar = _new_client(root, port)
        try:
            _assert_ok(registrar.send_request(ParsedCommand(ACTION_REGISTER, {"username": alice})))
            _assert_ok(registrar.send_request(ParsedCommand(ACTION_REGISTER, {"username": bob})))
        finally:
            registrar.close()

        alice_client = _new_client(root, port)
        try:
            login_response = alice_client.send_request(ParsedCommand(ACTION_LOGIN, {"username": alice}))
            _assert_ok(login_response)
            alice_client.current_user = login_response["data"]["username"]
            _assert_ok(
                alice_client.send_request(
                    ParsedCommand(
                        ACTION_SEND,
                        {"to": bob, "message": "ola segura em smoke test"},
                    )
                )
            )
        finally:
            alice_client.close()

        bob_client = _new_client(root, port)
        try:
            login_response = bob_client.send_request(ParsedCommand(ACTION_LOGIN, {"username": bob}))
            _assert_ok(login_response)
            bob_client.current_user = login_response["data"]["username"]

            inbox_response = bob_client.send_request(ParsedCommand(ACTION_INBOX))
            _assert_ok(inbox_response)
            messages = inbox_response.get("data", {}).get("messages", [])
            if not messages:
                raise AssertionError("Inbox smoke test nao devolveu a mensagem offline.")

            bob_client._display_inbox_messages(inbox_response["data"])
            time.sleep(0.2)

            empty_inbox_response = bob_client.send_request(ParsedCommand(ACTION_INBOX))
            _assert_ok(empty_inbox_response)
            if empty_inbox_response.get("data", {}).get("pending_messages") != 0:
                raise AssertionError("Ack smoke test nao limpou as mensagens pendentes.")
        finally:
            bob_client.close()

        if chat_server.server_socket is not None:
            chat_server.server_socket.close()

    print("Smoke test OK: TLS, register/login, envio E2EE offline, inbox e ack.")


def _configure_runtime_paths(root: Path) -> None:
    server_data = root / "server"
    client_tls = root / "client" / "tls"
    server_module.USERS_FILE = server_data / "users.json"
    server_module.MESSAGES_FILE = server_data / "messages.json"
    server_module.SERVER_CERT_FILE = server_data / "server_cert.pem"
    server_module.SERVER_KEY_FILE = server_data / "server_key.pem"

    import client.client as client_module

    client_module.TRUSTED_SERVER_CERT_FILE = client_tls / "trusted_server_cert.pem"
    client_module.TRUSTED_SERVER_FINGERPRINT_FILE = client_tls / "trusted_server_fingerprint.txt"


def _new_client(root: Path, port: int) -> ChatClient:
    key_manager = KeyManager(
        keys_dir=root / "client" / "keys",
        session_dir=root / "client" / "sessions",
    )
    client = ChatClient(host=DEFAULT_HOST, port=port, key_manager=key_manager)
    client.connect()
    return client


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((DEFAULT_HOST, 0))
        return int(sock.getsockname()[1])


def _wait_for_server_socket(chat_server: server_module.ChatServer) -> None:
    for _ in range(50):
        if chat_server.server_socket is not None:
            return
        time.sleep(0.1)
    raise RuntimeError("O servidor nao arrancou a tempo para o smoke test.")


def _assert_ok(response: dict) -> None:
    if response.get("status") != STATUS_OK:
        raise AssertionError(response.get("message", "Resposta inesperada no smoke test."))


if __name__ == "__main__":
    main()
