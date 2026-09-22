"""
Servidor principal do sistema de conversação seguro.

Gere ligações TCP/TLS, autenticação de utilizadores, despacho de ações
do protocolo, presença online e acesso às estruturas persistentes de
utilizadores e mensagens.
"""

import argparse
import secrets
import socket
import ssl
import sys
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from time import monotonic
from typing import Any

if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parents[1]))

from common.constants import (
    ACTION_ADD_CONTACT,
    ACTION_ACK_INBOX,
    ACTION_EXIT,
    ACTION_GET_USER_KEYS,
    ACTION_INBOX,
    ACTION_LIST_CONTACTS,
    ACTION_LOGIN,
    ACTION_LOGIN_CANCEL,
    ACTION_LOGIN_FINISH,
    ACTION_LOGIN_INIT,
    ACTION_ONLINE,
    ACTION_REGISTER,
    ACTION_SEND,
    DEFAULT_HOST,
    DEFAULT_MESSAGE_CONTENT_TYPE,
    DEFAULT_PORT,
    E2EE_ENCRYPTION_SUITE,
    E2EE_MESSAGE_CONTENT_TYPE,
    E2EE_MESSAGE_VERSION,
    E2EE_SESSION_ENCRYPTION_SUITE,
    E2EE_SESSION_MESSAGE_VERSION,
    E2EE_SIGNATURE_ALGORITHM,
    EVENT_INCOMING_MESSAGE,
    LOGIN_CHALLENGE_EXPIRATION_SECONDS,
    MAX_ACK_MESSAGE_IDS,
    MAX_ACTION_LENGTH,
    MAX_APPLICATION_PAYLOAD_SIZE,
    MAX_CIPHERTEXT_BYTES,
    MAX_CONTENT_TYPE_LENGTH,
    MAX_INBOX_MESSAGES,
    MAX_METADATA_FIELDS,
    MAX_METADATA_SIZE,
    MAX_REQUEST_ID_LENGTH,
    MESSAGE_STATUS_PENDING,
    MESSAGE_ID_HEX_LENGTH,
    MESSAGE_TYPE_EVENT,
    MESSAGE_TYPE_REQUEST,
    MESSAGE_TYPE_RESPONSE,
    MESSAGES_FILE,
    PREKEY_ID_HEX_LENGTH,
    SESSION_HEADER_TYPE_EXISTING,
    SESSION_HEADER_TYPE_INIT,
    SESSION_ID_HEX_LENGTH,
    SESSION_INIT_MODE_REPLY_PREKEY,
    SESSION_INIT_MODE_STATIC,
    SESSION_MAX_MESSAGES,
    SOCKET_BACKLOG,
    STATUS_ERROR,
    STATUS_OK,
    SERVER_CERT_FILE,
    SERVER_KEY_FILE,
    USERS_FILE,
)
from common.crypto_utils import (
    CryptoError,
    decode_base64_to_bytes,
    encode_bytes_to_base64,
    load_public_key_from_base64,
    load_x25519_public_key_from_base64,
    verify_signature,
)
from common.protocol import (
    ConnectionClosedError,
    ProtocolError,
    receive_message,
    send_message,
)
from common.tls_utils import TLSError, create_server_ssl_context
from common.validation import (
    clean_string,
    is_hex_token,
    is_safe_token,
    json_size_bytes,
    normalize_username,
    username_policy_message,
)
from server.message_store import MessageStore
from server.user_db import UserDatabase


@dataclass
class PendingLoginChallenge:
    username: str
    nonce: bytes
    issued_at: float


@dataclass
class ClientConnection:
    sock: socket.socket
    address: tuple[str, int]
    # Fonte de verdade da identidade autenticada desta ligação.
    authenticated_username: str | None = None
    pending_login: PendingLoginChallenge | None = None
    send_lock: threading.Lock = field(default_factory=threading.Lock)


AUTHENTICATED_ACTIONS = {
    ACTION_GET_USER_KEYS,
    ACTION_ADD_CONTACT,
    ACTION_LIST_CONTACTS,
    ACTION_ONLINE,
    ACTION_SEND,
    ACTION_INBOX,
    ACTION_ACK_INBOX,
}


class ChatServer:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.user_db = UserDatabase(USERS_FILE)
        self.message_store = MessageStore(MESSAGES_FILE)
        self.server_socket: socket.socket | None = None
        self.tls_context: ssl.SSLContext | None = None
        self.online_users: dict[str, ClientConnection] = {}
        self.online_lock = threading.RLock()

    def start(self) -> None:
        try:
            self.tls_context = create_server_ssl_context(SERVER_CERT_FILE, SERVER_KEY_FILE)
        except TLSError as exc:
            print(f"[SERVER] TLS configuration error: {exc}", flush=True)
            return

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(SOCKET_BACKLOG)

        print(f"[SERVER] Listening on {self.host}:{self.port}", flush=True)

        try:
            while True:
                client_socket, address = self.server_socket.accept()
                try:
                    tls_client_socket = self._wrap_tls_client_socket(client_socket)
                except ssl.SSLError as exc:
                    print(
                        f"[SERVER] TLS handshake failed from {address}: {exc}",
                        flush=True,
                    )
                    try:
                        client_socket.close()
                    except OSError:
                        pass
                    continue

                connection = ClientConnection(sock=tls_client_socket, address=address)
                print(f"[SERVER] New connection from {address}", flush=True)
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(connection,),
                    daemon=True,
                )
                client_thread.start()
        except KeyboardInterrupt:
            print("\n[SERVER] Shutting down.", flush=True)
        finally:
            if self.server_socket is not None:
                self.server_socket.close()

    def _wrap_tls_client_socket(self, client_socket: socket.socket) -> ssl.SSLSocket:
        if self.tls_context is None:
            raise ssl.SSLError("TLS context not initialized.")
        return self.tls_context.wrap_socket(client_socket, server_side=True)

    def _handle_client(self, connection: ClientConnection) -> None:
        should_close = False

        try:
            while not should_close:
                request = receive_message(connection.sock)
                response, should_close = self._dispatch_request(connection, request)
                self._safe_send(connection, response)
        except ConnectionClosedError:
            print(f"[SERVER] Connection closed: {connection.address}", flush=True)
        except ProtocolError as exc:
            print(f"[SERVER] Protocol error from {connection.address}: {exc}", flush=True)
            self._send_error_without_request(
                connection,
                "protocol_error",
                f"Mensagem invalida: {exc}",
            )
        except OSError as exc:
            print(f"[SERVER] Socket error from {connection.address}: {exc}", flush=True)
        except Exception as exc:
            print(
                f"[SERVER] Unexpected error from {connection.address}: {type(exc).__name__}",
                flush=True,
            )
            self._send_error_without_request(
                connection,
                "server_error",
                "O servidor encontrou um erro ao processar o pedido.",
            )
        finally:
            self._unregister_online_user(connection)
            try:
                connection.sock.close()
            except OSError:
                pass

    def _dispatch_request(
        self, connection: ClientConnection, request: dict[str, Any]
    ) -> tuple[dict[str, Any], bool]:
        validation_error = self._validate_request_message(request)
        if validation_error is not None:
            return validation_error, False

        action = request["action"]
        payload = request.get("payload", {})

        handlers = {
            ACTION_REGISTER: self._handle_register,
            ACTION_LOGIN: self._handle_login_alias,
            ACTION_LOGIN_INIT: self._handle_login_init,
            ACTION_LOGIN_FINISH: self._handle_login_finish,
            ACTION_LOGIN_CANCEL: self._handle_login_cancel,
            ACTION_GET_USER_KEYS: self._handle_get_user_keys,
            ACTION_ADD_CONTACT: self._handle_add_contact,
            ACTION_LIST_CONTACTS: self._handle_list_contacts,
            ACTION_ONLINE: self._handle_online,
            ACTION_SEND: self._handle_send_message,
            ACTION_INBOX: self._handle_inbox,
            ACTION_ACK_INBOX: self._handle_ack_inbox,
            ACTION_EXIT: self._handle_exit,
        }

        handler = handlers.get(action)
        if handler is None:
            return (
                self._make_response(
                    request,
                    STATUS_ERROR,
                    action,
                    "Acao desconhecida.",
                ),
                False,
            )

        # Ações sensíveis dependem sempre da identidade autenticada na sessão.
        if action in AUTHENTICATED_ACTIONS and connection.authenticated_username is None:
            return self._authentication_required_response(request, action), False

        response = handler(connection, request, payload)
        should_close = action == ACTION_EXIT and response["status"] == STATUS_OK
        return response, should_close

    def _handle_register(
        self, connection: ClientConnection, request: dict[str, Any], payload: dict[str, Any]
    ) -> dict[str, Any]:
        validation_error = self._validate_payload_fields(
            request,
            ACTION_REGISTER,
            payload,
            required_fields={"username", "public_keys"},
        )
        if validation_error is not None:
            return validation_error

        username = self._clean_username(payload.get("username"))
        if not username:
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_REGISTER,
                username_policy_message(),
            )

        public_keys = payload.get("public_keys")
        if not isinstance(public_keys, dict):
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_REGISTER,
                "O campo public_keys tem de ser um objeto JSON.",
            )
        public_keys_error = self._validate_public_keys_payload(
            request,
            ACTION_REGISTER,
            public_keys,
            required_fields={"ed25519", "x25519"},
        )
        if public_keys_error is not None:
            return public_keys_error

        ed25519_public_key = self._clean_string(public_keys.get("ed25519"))
        x25519_public_key = self._clean_string(public_keys.get("x25519"))
        if not ed25519_public_key or not x25519_public_key:
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_REGISTER,
                "O registo exige public keys Ed25519 e X25519.",
            )

        try:
            load_public_key_from_base64(ed25519_public_key)
            load_x25519_public_key_from_base64(x25519_public_key)
        except CryptoError as exc:
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_REGISTER,
                str(exc),
            )

        if not self.user_db.register_user(
            username,
            ed25519_public_key=ed25519_public_key,
            x25519_public_key=x25519_public_key,
        ):
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_REGISTER,
                "Esse username ja existe.",
            )

        self.message_store.ensure_user(username)
        return self._make_response(
            request,
            STATUS_OK,
            ACTION_REGISTER,
            "Utilizador registado com sucesso.",
            {"username": username},
        )

    def _handle_login_alias(
        self, connection: ClientConnection, request: dict[str, Any], payload: dict[str, Any]
    ) -> dict[str, Any]:
        return self._make_response(
            request,
            STATUS_ERROR,
            ACTION_LOGIN,
            "Use o fluxo login_init/login_finish. O cliente trata disso automaticamente.",
        )

    def _handle_login_init(
        self, connection: ClientConnection, request: dict[str, Any], payload: dict[str, Any]
    ) -> dict[str, Any]:
        validation_error = self._validate_payload_fields(
            request,
            ACTION_LOGIN_INIT,
            payload,
            required_fields={"username"},
        )
        if validation_error is not None:
            return validation_error

        username = self._clean_username(payload.get("username"))
        if not username:
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_LOGIN_INIT,
                username_policy_message(),
            )

        if connection.authenticated_username is not None:
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_LOGIN_INIT,
                "Este cliente ja esta autenticado.",
            )

        if not self.user_db.user_exists(username):
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_LOGIN_INIT,
                "Esse utilizador nao esta registado.",
            )

        with self.online_lock:
            if username in self.online_users:
                return self._make_response(
                    request,
                    STATUS_ERROR,
                    ACTION_LOGIN_INIT,
                    "Esse utilizador ja tem uma sessao ativa.",
                )

        # Cada login_init substitui desafios antigos desta ligação.
        self._clear_pending_login(connection)
        nonce = secrets.token_bytes(32)
        connection.pending_login = PendingLoginChallenge(
            username=username,
            nonce=nonce,
            issued_at=monotonic(),
        )

        return self._make_response(
            request,
            STATUS_OK,
            ACTION_LOGIN_INIT,
            "Desafio de autenticacao gerado.",
            {
                "username": username,
                "nonce": encode_bytes_to_base64(nonce),
            },
        )

    def _handle_login_finish(
        self, connection: ClientConnection, request: dict[str, Any], payload: dict[str, Any]
    ) -> dict[str, Any]:
        validation_error = self._validate_payload_fields(
            request,
            ACTION_LOGIN_FINISH,
            payload,
            required_fields={"username", "signature"},
            optional_fields={"ed25519_public_key", "x25519_public_key"},
        )
        if validation_error is not None:
            return validation_error

        username = self._clean_username(payload.get("username"))
        signature_b64 = self._clean_string(payload.get("signature"))
        ed25519_public_key = self._clean_string(payload.get("ed25519_public_key"))
        x25519_public_key = self._clean_string(payload.get("x25519_public_key"))
        if not username:
            self._clear_pending_login(connection)
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_LOGIN_FINISH,
                username_policy_message(),
            )

        if connection.authenticated_username is not None:
            self._clear_pending_login(connection)
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_LOGIN_FINISH,
                "Este cliente ja esta autenticado.",
            )

        pending_login = connection.pending_login
        if pending_login is None:
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_LOGIN_FINISH,
                "Nao existe um login_init valido para esta ligacao.",
            )

        if pending_login.username != username:
            self._clear_pending_login(connection)
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_LOGIN_FINISH,
                "O username do login_finish nao corresponde ao desafio pendente.",
            )

        if monotonic() - pending_login.issued_at > LOGIN_CHALLENGE_EXPIRATION_SECONDS:
            self._clear_pending_login(connection)
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_LOGIN_FINISH,
                "O nonce de autenticacao expirou. Inicie novo login.",
            )

        public_key_b64 = self.user_db.get_ed25519_public_key(username)
        if public_key_b64 is None:
            self._clear_pending_login(connection)
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_LOGIN_FINISH,
                "O utilizador nao tem uma chave publica Ed25519 registada.",
            )

        try:
            public_key = load_public_key_from_base64(public_key_b64)
            signature = decode_base64_to_bytes(signature_b64)
        except CryptoError as exc:
            self._clear_pending_login(connection)
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_LOGIN_FINISH,
                str(exc),
            )
        if len(signature) != 64:
            self._clear_pending_login(connection)
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_LOGIN_FINISH,
                "A assinatura Ed25519 tem tamanho invalido.",
            )

        # O login só termina após validação da assinatura Ed25519 sobre o nonce.
        if not verify_signature(public_key, pending_login.nonce, signature):
            self._clear_pending_login(connection)
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_LOGIN_FINISH,
                "A assinatura do desafio e invalida.",
            )

        with self.online_lock:
            if username in self.online_users:
                self._clear_pending_login(connection)
                return self._make_response(
                    request,
                    STATUS_ERROR,
                    ACTION_LOGIN_FINISH,
                    "Esse utilizador ja tem uma sessao ativa.",
                )

        if x25519_public_key:
            try:
                load_x25519_public_key_from_base64(x25519_public_key)
            except CryptoError as exc:
                self._clear_pending_login(connection)
                return self._make_response(
                    request,
                    STATUS_ERROR,
                    ACTION_LOGIN_FINISH,
                    str(exc),
                )

        if ed25519_public_key:
            try:
                load_public_key_from_base64(ed25519_public_key)
            except CryptoError as exc:
                self._clear_pending_login(connection)
                return self._make_response(
                    request,
                    STATUS_ERROR,
                    ACTION_LOGIN_FINISH,
                    str(exc),
                )

        sync_success, sync_message = self.user_db.ensure_user_public_keys(
            username,
            ed25519_public_key=ed25519_public_key,
            x25519_public_key=x25519_public_key,
        )
        if not sync_success:
            self._clear_pending_login(connection)
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_LOGIN_FINISH,
                sync_message,
            )

        with self.online_lock:
            if username in self.online_users:
                self._clear_pending_login(connection)
                return self._make_response(
                    request,
                    STATUS_ERROR,
                    ACTION_LOGIN_FINISH,
                    "Esse utilizador ja tem uma sessao ativa.",
                )
            connection.authenticated_username = username
            self.online_users[username] = connection

        self._clear_pending_login(connection)
        pending_count = self.message_store.get_pending_count(username)
        return self._make_response(
            request,
            STATUS_OK,
            ACTION_LOGIN_FINISH,
            "Login efetuado com sucesso.",
            {
                "username": username,
                "pending_messages": pending_count,
            },
        )

    def _handle_login_cancel(
        self, connection: ClientConnection, request: dict[str, Any], payload: dict[str, Any]
    ) -> dict[str, Any]:
        validation_error = self._validate_payload_fields(
            request,
            ACTION_LOGIN_CANCEL,
            payload,
            required_fields={"username"},
        )
        if validation_error is not None:
            return validation_error

        username = self._clean_username(payload.get("username"))
        pending_login = connection.pending_login
        if pending_login is None:
            return self._make_response(
                request,
                STATUS_OK,
                ACTION_LOGIN_CANCEL,
                "Nao existia desafio pendente.",
            )

        if username and pending_login.username != username:
            self._clear_pending_login(connection)
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_LOGIN_CANCEL,
                "O username indicado nao corresponde ao desafio pendente.",
            )

        self._clear_pending_login(connection)
        return self._make_response(
            request,
            STATUS_OK,
            ACTION_LOGIN_CANCEL,
            "Desafio de autenticacao cancelado.",
        )

    def _handle_get_user_keys(
        self, connection: ClientConnection, request: dict[str, Any], payload: dict[str, Any]
    ) -> dict[str, Any]:
        _, auth_error = self._require_authenticated_username(
            connection,
            request,
            ACTION_GET_USER_KEYS,
        )
        if auth_error is not None:
            return auth_error

        validation_error = self._validate_payload_fields(
            request,
            ACTION_GET_USER_KEYS,
            payload,
            required_fields={"username"},
        )
        if validation_error is not None:
            return validation_error

        username = self._clean_username(payload.get("username"))
        if not username:
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_GET_USER_KEYS,
                username_policy_message(),
            )

        public_keys = self.user_db.get_public_keys(username)
        if public_keys is None:
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_GET_USER_KEYS,
                "O utilizador pedido nao existe.",
            )

        missing_key_names = sorted(
            key_name for key_name in ("ed25519", "x25519") if not self._clean_string(public_keys.get(key_name))
        )
        if missing_key_names:
            missing = ", ".join(missing_key_names)
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_GET_USER_KEYS,
                f"O utilizador pedido nao tem todas as chaves publicas registadas: {missing}.",
            )

        return self._make_response(
            request,
            STATUS_OK,
            ACTION_GET_USER_KEYS,
            "Chaves publicas carregadas com sucesso.",
            {
                "username": username,
                "public_keys": public_keys,
            },
        )

    def _handle_add_contact(
        self, connection: ClientConnection, request: dict[str, Any], payload: dict[str, Any]
    ) -> dict[str, Any]:
        session_username, auth_error = self._require_authenticated_username(
            connection,
            request,
            ACTION_ADD_CONTACT,
        )
        if auth_error is not None:
            return auth_error

        validation_error = self._validate_payload_fields(
            request,
            ACTION_ADD_CONTACT,
            payload,
            required_fields={"username"},
        )
        if validation_error is not None:
            return validation_error

        contact_username = self._clean_username(payload.get("username"))
        if not contact_username:
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_ADD_CONTACT,
                username_policy_message(),
            )

        success, message = self.user_db.add_contact(session_username, contact_username)
        status = STATUS_OK if success else STATUS_ERROR
        return self._make_response(request, status, ACTION_ADD_CONTACT, message)

    def _handle_list_contacts(
        self, connection: ClientConnection, request: dict[str, Any], payload: dict[str, Any]
    ) -> dict[str, Any]:
        session_username, auth_error = self._require_authenticated_username(
            connection,
            request,
            ACTION_LIST_CONTACTS,
        )
        if auth_error is not None:
            return auth_error

        validation_error = self._validate_payload_fields(
            request,
            ACTION_LIST_CONTACTS,
            payload,
        )
        if validation_error is not None:
            return validation_error

        contacts = self.user_db.list_contacts(session_username)
        return self._make_response(
            request,
            STATUS_OK,
            ACTION_LIST_CONTACTS,
            "Lista de contactos carregada.",
            {"contacts": contacts},
        )

    def _handle_online(
        self, connection: ClientConnection, request: dict[str, Any], payload: dict[str, Any]
    ) -> dict[str, Any]:
        _, auth_error = self._require_authenticated_username(
            connection,
            request,
            ACTION_ONLINE,
        )
        if auth_error is not None:
            return auth_error

        validation_error = self._validate_payload_fields(
            request,
            ACTION_ONLINE,
            payload,
        )
        if validation_error is not None:
            return validation_error

        with self.online_lock:
            online_users = sorted(self.online_users.keys())

        return self._make_response(
            request,
            STATUS_OK,
            ACTION_ONLINE,
            "Lista de utilizadores online carregada.",
            {"online_users": online_users},
        )

    def _handle_send_message(
        self, connection: ClientConnection, request: dict[str, Any], payload: dict[str, Any]
    ) -> dict[str, Any]:
        session_username, auth_error = self._require_authenticated_username(
            connection,
            request,
            ACTION_SEND,
        )
        if auth_error is not None:
            return auth_error

        # O remetente real vem da sessão autenticada, não do payload do cliente.
        parsed_send_request, validation_error = self._parse_send_request(request, payload)
        if validation_error is not None:
            return validation_error

        recipient = parsed_send_request["recipient"]
        if recipient == session_username:
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_SEND,
                "Nao pode enviar mensagens para si proprio nesta etapa.",
            )

        if not self.user_db.user_exists(recipient):
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_SEND,
                "O utilizador de destino nao existe.",
            )

        message_envelope = self._build_message_envelope(
            sender=session_username,
            recipient=recipient,
            opaque_payload=parsed_send_request["payload"],
            metadata=parsed_send_request["metadata"],
        )
        stored_message = self.message_store.store_message(recipient, message_envelope)

        self._notify_user_of_new_message(recipient, stored_message)

        delivery_state = "queued"
        with self.online_lock:
            if recipient in self.online_users:
                delivery_state = "online_notification_sent"

        return self._make_response(
            request,
            STATUS_OK,
            ACTION_SEND,
            f"Mensagem enviada para {recipient}.",
            {
                "delivery": delivery_state,
                "message_id": stored_message["message_id"],
            },
        )

    def _handle_inbox(
        self, connection: ClientConnection, request: dict[str, Any], payload: dict[str, Any]
    ) -> dict[str, Any]:
        session_username, auth_error = self._require_authenticated_username(
            connection,
            request,
            ACTION_INBOX,
        )
        if auth_error is not None:
            return auth_error

        validation_error = self._validate_payload_fields(
            request,
            ACTION_INBOX,
            payload,
        )
        if validation_error is not None:
            return validation_error

        # A inbox devolve apenas mensagens ainda pendentes para o utilizador autenticado.
        messages = self.message_store.list_messages(
            session_username,
            statuses={MESSAGE_STATUS_PENDING},
            limit=MAX_INBOX_MESSAGES,
        )
        pending_count = self.message_store.get_pending_count(session_username)

        return self._make_response(
            request,
            STATUS_OK,
            ACTION_INBOX,
            "Inbox carregada com sucesso.",
            {
                "messages": messages,
                "pending_messages": pending_count,
                "returned_messages": len(messages),
                "max_returned_messages": MAX_INBOX_MESSAGES,
            },
        )

    def _handle_ack_inbox(
        self, connection: ClientConnection, request: dict[str, Any], payload: dict[str, Any]
    ) -> dict[str, Any]:
        session_username, auth_error = self._require_authenticated_username(
            connection,
            request,
            ACTION_ACK_INBOX,
        )
        if auth_error is not None:
            return auth_error

        validation_error = self._validate_payload_fields(
            request,
            ACTION_ACK_INBOX,
            payload,
            required_fields={"message_ids"},
        )
        if validation_error is not None:
            return validation_error

        raw_message_ids = payload.get("message_ids")
        if not isinstance(raw_message_ids, list):
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_ACK_INBOX,
                "O campo message_ids tem de ser uma lista JSON.",
            )
        if len(raw_message_ids) > MAX_ACK_MESSAGE_IDS:
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_ACK_INBOX,
                f"O ack nao pode confirmar mais de {MAX_ACK_MESSAGE_IDS} mensagens de uma vez.",
            )

        message_ids: list[str] = []
        seen_message_ids: set[str] = set()
        for raw_message_id in raw_message_ids:
            message_id = self._clean_string(raw_message_id)
            if not is_hex_token(message_id, length=MESSAGE_ID_HEX_LENGTH):
                return self._make_response(
                    request,
                    STATUS_ERROR,
                    ACTION_ACK_INBOX,
                    "Todos os message_ids do ack tem de ser hexadecimais de 32 caracteres.",
                )
            if message_id in seen_message_ids:
                continue
            seen_message_ids.add(message_id)
            message_ids.append(message_id)

        if not message_ids:
            return self._make_response(
                request,
                STATUS_OK,
                ACTION_ACK_INBOX,
                "Nenhuma mensagem para confirmar.",
                {
                    "acknowledged_count": 0,
                    "already_delivered_count": 0,
                    "unknown_count": 0,
                    "remaining_pending": self.message_store.get_pending_count(session_username),
                },
            )

        # Uma mensagem só passa a delivered depois da confirmação explícita do cliente.
        ack_result = self.message_store.acknowledge_messages(
            session_username,
            message_ids,
            delivered_at=datetime.now(timezone.utc).isoformat(),
        )
        return self._make_response(
            request,
            STATUS_OK,
            ACTION_ACK_INBOX,
            "Ack de entrega processado.",
            {
                "acknowledged_count": len(ack_result["acknowledged_ids"]),
                "already_delivered_count": len(ack_result["already_delivered_ids"]),
                "unknown_count": len(ack_result["unknown_ids"]),
                "acknowledged_ids": ack_result["acknowledged_ids"],
                "already_delivered_ids": ack_result["already_delivered_ids"],
                "unknown_ids": ack_result["unknown_ids"],
                "remaining_pending": self.message_store.get_pending_count(session_username),
            },
        )

    def _handle_exit(
        self, connection: ClientConnection, request: dict[str, Any], payload: dict[str, Any]
    ) -> dict[str, Any]:
        validation_error = self._validate_payload_fields(
            request,
            ACTION_EXIT,
            payload,
        )
        if validation_error is not None:
            return validation_error

        self._clear_pending_login(connection)
        return self._make_response(
            request,
            STATUS_OK,
            ACTION_EXIT,
            "Ligacao terminada.",
        )

    def _notify_user_of_new_message(
        self, username: str, message_record: dict[str, Any]
    ) -> None:
        with self.online_lock:
            connection = self.online_users.get(username)

        if connection is None:
            return

        event_payload = {
            "type": MESSAGE_TYPE_EVENT,
            "event": EVENT_INCOMING_MESSAGE,
            "message": f"Nova mensagem de {message_record['sender']}. Use /inbox para consultar.",
            "data": {
                "message_id": message_record["message_id"],
                "sender": message_record["sender"],
                "timestamp": message_record["timestamp"],
            },
        }

        try:
            self._safe_send(connection, event_payload)
        except OSError:
            self._unregister_online_user(connection)

    def _safe_send(self, connection: ClientConnection, payload: dict[str, Any]) -> None:
        with connection.send_lock:
            send_message(connection.sock, payload)

    def _send_error_without_request(
        self, connection: ClientConnection, action: str, message: str
    ) -> None:
        payload = {
            "type": MESSAGE_TYPE_RESPONSE,
            "request_id": None,
            "action": action,
            "status": STATUS_ERROR,
            "message": message,
            "data": {},
        }
        try:
            self._safe_send(connection, payload)
        except OSError:
            pass

    def _make_response(
        self,
        request: dict[str, Any],
        status: str,
        action: str,
        message: str,
        data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        request_id = request.get("request_id") if isinstance(request, dict) else None
        if not is_safe_token(request_id, max_length=MAX_REQUEST_ID_LENGTH):
            request_id = None
        return {
            "type": MESSAGE_TYPE_RESPONSE,
            "request_id": request_id,
            "action": action,
            "status": status,
            "message": message,
            "data": data or {},
        }

    def _authentication_required_response(
        self, request: dict[str, Any], action: str
    ) -> dict[str, Any]:
        return self._make_response(
            request,
            STATUS_ERROR,
            action,
            "Tem de fazer login antes de usar este comando.",
        )

    def _validate_request_message(self, request: dict[str, Any]) -> dict[str, Any] | None:
        if not isinstance(request, dict):
            return self._make_response(
                {},
                STATUS_ERROR,
                "invalid_type",
                "A mensagem recebida tem de ser um objeto JSON.",
            )

        if request.get("type") != MESSAGE_TYPE_REQUEST:
            return self._make_response(
                request,
                STATUS_ERROR,
                "invalid_type",
                "Mensagem recebida com tipo invalido.",
            )

        request_id = request.get("request_id")
        action = request.get("action")
        action_name = self._safe_action_name(action)

        if not is_safe_token(request_id, max_length=MAX_REQUEST_ID_LENGTH):
            return self._make_response(
                request,
                STATUS_ERROR,
                action_name,
                "O campo request_id tem de ser um token nao vazio e curto.",
            )

        if not is_safe_token(action, max_length=MAX_ACTION_LENGTH):
            return self._make_response(
                request,
                STATUS_ERROR,
                "unknown",
                "O campo action tem de ser um token nao vazio e curto.",
            )

        payload = request.get("payload", {})
        if not isinstance(payload, dict):
            return self._make_response(
                request,
                STATUS_ERROR,
                action,
                "O campo payload tem de ser um objeto JSON.",
            )
        if json_size_bytes(payload) > MAX_APPLICATION_PAYLOAD_SIZE:
            return self._make_response(
                request,
                STATUS_ERROR,
                action,
                "O payload aplicacional excede o tamanho maximo permitido.",
            )

        return None

    def _validate_payload_fields(
        self,
        request: dict[str, Any],
        action: str,
        payload: dict[str, Any],
        *,
        required_fields: set[str] | None = None,
        optional_fields: set[str] | None = None,
    ) -> dict[str, Any] | None:
        required = required_fields or set()
        optional = optional_fields or set()
        allowed_fields = required | optional

        missing_fields = sorted(field for field in required if field not in payload)
        if missing_fields:
            missing = ", ".join(missing_fields)
            return self._make_response(
                request,
                STATUS_ERROR,
                action,
                f"Faltam campos obrigatorios no payload: {missing}.",
            )

        unexpected_fields = sorted(field for field in payload if field not in allowed_fields)
        if unexpected_fields:
            unexpected = ", ".join(unexpected_fields)
            return self._make_response(
                request,
                STATUS_ERROR,
                action,
                f"O payload contem campos inesperados: {unexpected}.",
            )

        return None

    def _validate_public_keys_payload(
        self,
        request: dict[str, Any],
        action: str,
        public_keys: dict[str, Any],
        *,
        required_fields: set[str],
    ) -> dict[str, Any] | None:
        missing_fields = sorted(field for field in required_fields if field not in public_keys)
        if missing_fields:
            missing = ", ".join(missing_fields)
            return self._make_response(
                request,
                STATUS_ERROR,
                action,
                f"Faltam public keys obrigatorias: {missing}.",
            )

        unexpected_fields = sorted(field for field in public_keys if field not in {"ed25519", "x25519"})
        if unexpected_fields:
            unexpected = ", ".join(str(field) for field in unexpected_fields[:5])
            return self._make_response(
                request,
                STATUS_ERROR,
                action,
                f"O campo public_keys contem campos inesperados: {unexpected}.",
            )

        if json_size_bytes(public_keys) > 512:
            return self._make_response(
                request,
                STATUS_ERROR,
                action,
                "O campo public_keys excede o tamanho maximo permitido.",
            )
        return None

    def _validate_metadata(
        self,
        request: dict[str, Any],
        action: str,
        metadata: Any,
    ) -> dict[str, Any] | None:
        if not isinstance(metadata, dict):
            return self._make_response(
                request,
                STATUS_ERROR,
                action,
                "O campo metadata tem de ser um objeto JSON.",
            )
        if len(metadata) > MAX_METADATA_FIELDS:
            return self._make_response(
                request,
                STATUS_ERROR,
                action,
                f"O campo metadata nao pode ter mais de {MAX_METADATA_FIELDS} campos.",
            )
        if json_size_bytes(metadata) > MAX_METADATA_SIZE:
            return self._make_response(
                request,
                STATUS_ERROR,
                action,
                "O campo metadata excede o tamanho maximo permitido.",
            )

        for key in metadata:
            if not isinstance(key, str) or not key or len(key) > 64:
                return self._make_response(
                    request,
                    STATUS_ERROR,
                    action,
                    "Todos os nomes em metadata tem de ser strings curtas nao vazias.",
                )

        version = metadata.get("version")
        if version is not None and version not in {E2EE_MESSAGE_VERSION, E2EE_SESSION_MESSAGE_VERSION}:
            return self._make_response(
                request,
                STATUS_ERROR,
                action,
                "A version em metadata nao e suportada.",
            )

        session_id = metadata.get("session_id")
        if session_id is not None and not is_hex_token(session_id, length=SESSION_ID_HEX_LENGTH):
            return self._make_response(
                request,
                STATUS_ERROR,
                action,
                "O session_id em metadata tem formato invalido.",
            )

        session_counter = metadata.get("session_counter")
        if session_counter is not None and (
            isinstance(session_counter, bool)
            or not isinstance(session_counter, int)
            or session_counter < 0
            or session_counter >= SESSION_MAX_MESSAGES
        ):
            return self._make_response(
                request,
                STATUS_ERROR,
                action,
                "O session_counter em metadata tem formato invalido.",
            )

        signed = metadata.get("signed")
        if signed is not None and not isinstance(signed, bool):
            return self._make_response(
                request,
                STATUS_ERROR,
                action,
                "O campo signed em metadata tem de ser booleano.",
            )

        return None

    def _validate_e2ee_body(
        self,
        request: dict[str, Any],
        body: dict[str, Any],
    ) -> dict[str, Any] | None:
        if json_size_bytes(body) > MAX_APPLICATION_PAYLOAD_SIZE:
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_SEND,
                "O body E2EE excede o tamanho maximo permitido.",
            )

        version = body.get("version")
        if version == E2EE_MESSAGE_VERSION:
            return self._validate_legacy_e2ee_body(request, body)
        if version == E2EE_SESSION_MESSAGE_VERSION:
            return self._validate_session_e2ee_body(request, body)

        return self._make_response(
            request,
            STATUS_ERROR,
            ACTION_SEND,
            "A versao do body E2EE nao e suportada.",
        )

    def _validate_legacy_e2ee_body(
        self,
        request: dict[str, Any],
        body: dict[str, Any],
    ) -> dict[str, Any] | None:
        allowed_fields = {
            "version",
            "encryption",
            "inner_content_type",
            "ephemeral_public_key",
            "nonce",
            "ciphertext",
            "signature_algorithm",
            "signature",
        }
        field_error = self._validate_exact_body_fields(request, body, allowed_fields)
        if field_error is not None:
            return field_error

        if self._clean_string(body.get("encryption")) != E2EE_ENCRYPTION_SUITE:
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_SEND,
                "O algoritmo E2EE legacy nao e suportado.",
            )
        if self._clean_string(body.get("inner_content_type")) != DEFAULT_MESSAGE_CONTENT_TYPE:
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_SEND,
                "O content_type interno da mensagem nao e suportado.",
            )

        public_key_error = self._validate_x25519_public_key_field(
            request,
            "ephemeral_public_key",
            body.get("ephemeral_public_key"),
        )
        if public_key_error is not None:
            return public_key_error
        return self._validate_crypto_blob_fields(request, body)

    def _validate_session_e2ee_body(
        self,
        request: dict[str, Any],
        body: dict[str, Any],
    ) -> dict[str, Any] | None:
        allowed_fields = {
            "version",
            "encryption",
            "inner_content_type",
            "session_id",
            "counter",
            "session_header",
            "reply_prekey",
            "nonce",
            "ciphertext",
            "signature_algorithm",
            "signature",
        }
        field_error = self._validate_exact_body_fields(request, body, allowed_fields)
        if field_error is not None:
            return field_error

        if self._clean_string(body.get("encryption")) != E2EE_SESSION_ENCRYPTION_SUITE:
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_SEND,
                "O algoritmo E2EE de sessao nao e suportado.",
            )
        if self._clean_string(body.get("inner_content_type")) != DEFAULT_MESSAGE_CONTENT_TYPE:
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_SEND,
                "O content_type interno da mensagem nao e suportado.",
            )
        if not is_hex_token(body.get("session_id"), length=SESSION_ID_HEX_LENGTH):
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_SEND,
                "O session_id tem de ser hexadecimal de 32 caracteres.",
            )

        counter = body.get("counter")
        if (
            isinstance(counter, bool)
            or not isinstance(counter, int)
            or counter < 0
            or counter >= SESSION_MAX_MESSAGES
        ):
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_SEND,
                "O counter da sessao tem de ser um inteiro no intervalo permitido.",
            )

        header_error = self._validate_session_header(request, body.get("session_header"))
        if header_error is not None:
            return header_error
        reply_prekey_error = self._validate_reply_prekey(request, body.get("reply_prekey"))
        if reply_prekey_error is not None:
            return reply_prekey_error
        return self._validate_crypto_blob_fields(request, body)

    def _validate_exact_body_fields(
        self,
        request: dict[str, Any],
        body: dict[str, Any],
        allowed_fields: set[str],
    ) -> dict[str, Any] | None:
        missing_fields = sorted(field for field in allowed_fields if field not in body)
        if missing_fields:
            missing = ", ".join(missing_fields)
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_SEND,
                f"Faltam campos obrigatorios no body E2EE: {missing}.",
            )

        unexpected_fields = sorted(field for field in body if field not in allowed_fields)
        if unexpected_fields:
            unexpected = ", ".join(str(field) for field in unexpected_fields[:5])
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_SEND,
                f"O body E2EE contem campos inesperados: {unexpected}.",
            )
        return None

    def _validate_session_header(
        self,
        request: dict[str, Any],
        session_header: Any,
    ) -> dict[str, Any] | None:
        if not isinstance(session_header, dict):
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_SEND,
                "O session_header tem de ser um objeto JSON.",
            )

        header_type = self._clean_string(session_header.get("type"))
        if header_type == SESSION_HEADER_TYPE_EXISTING:
            allowed_fields = {"type"}
        elif header_type == SESSION_HEADER_TYPE_INIT:
            allowed_fields = {"type", "init_mode", "session_public_key", "peer_reply_prekey_id"}
        else:
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_SEND,
                "O type do session_header nao e suportado.",
            )

        unexpected_fields = sorted(field for field in session_header if field not in allowed_fields)
        if unexpected_fields:
            unexpected = ", ".join(str(field) for field in unexpected_fields[:5])
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_SEND,
                f"O session_header contem campos inesperados: {unexpected}.",
            )

        if header_type == SESSION_HEADER_TYPE_EXISTING:
            return None

        init_mode = self._clean_string(session_header.get("init_mode"))
        if init_mode not in {SESSION_INIT_MODE_STATIC, SESSION_INIT_MODE_REPLY_PREKEY}:
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_SEND,
                "O init_mode da sessao nao e suportado.",
            )

        public_key_error = self._validate_x25519_public_key_field(
            request,
            "session_public_key",
            session_header.get("session_public_key"),
        )
        if public_key_error is not None:
            return public_key_error

        peer_reply_prekey_id = self._clean_string(session_header.get("peer_reply_prekey_id"))
        if peer_reply_prekey_id and not is_hex_token(
            peer_reply_prekey_id,
            length=PREKEY_ID_HEX_LENGTH,
        ):
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_SEND,
                "O peer_reply_prekey_id tem formato invalido.",
            )
        if init_mode == SESSION_INIT_MODE_REPLY_PREKEY and not peer_reply_prekey_id:
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_SEND,
                "O modo reply_prekey_x25519 exige peer_reply_prekey_id.",
            )
        return None

    def _validate_reply_prekey(
        self,
        request: dict[str, Any],
        reply_prekey: Any,
    ) -> dict[str, Any] | None:
        if not isinstance(reply_prekey, dict):
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_SEND,
                "A reply_prekey tem de ser um objeto JSON.",
            )
        unexpected_fields = sorted(field for field in reply_prekey if field not in {"prekey_id", "public_key"})
        if unexpected_fields:
            unexpected = ", ".join(str(field) for field in unexpected_fields[:5])
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_SEND,
                f"A reply_prekey contem campos inesperados: {unexpected}.",
            )
        if not is_hex_token(reply_prekey.get("prekey_id"), length=PREKEY_ID_HEX_LENGTH):
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_SEND,
                "O prekey_id da reply_prekey tem formato invalido.",
            )
        return self._validate_x25519_public_key_field(
            request,
            "reply_prekey.public_key",
            reply_prekey.get("public_key"),
        )

    def _validate_crypto_blob_fields(
        self,
        request: dict[str, Any],
        body: dict[str, Any],
    ) -> dict[str, Any] | None:
        if self._clean_string(body.get("signature_algorithm")) != E2EE_SIGNATURE_ALGORITHM:
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_SEND,
                "A assinatura da mensagem tem de usar Ed25519.",
            )

        for field_name, expected_size, max_size in (
            ("nonce", 12, None),
            ("signature", 64, None),
            ("ciphertext", None, MAX_CIPHERTEXT_BYTES),
        ):
            blob_error = self._validate_base64_field(
                request,
                field_name,
                body.get(field_name),
                expected_size=expected_size,
                max_size=max_size,
                min_size=1,
            )
            if blob_error is not None:
                return blob_error
        return None

    def _validate_x25519_public_key_field(
        self,
        request: dict[str, Any],
        field_name: str,
        value: Any,
    ) -> dict[str, Any] | None:
        public_key = self._clean_string(value)
        try:
            load_x25519_public_key_from_base64(public_key)
        except CryptoError:
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_SEND,
                f"O campo {field_name} nao contem uma public key X25519 valida.",
            )
        return None

    def _validate_base64_field(
        self,
        request: dict[str, Any],
        field_name: str,
        value: Any,
        *,
        expected_size: int | None = None,
        max_size: int | None = None,
        min_size: int = 0,
    ) -> dict[str, Any] | None:
        try:
            decoded = decode_base64_to_bytes(self._clean_string(value))
        except CryptoError:
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_SEND,
                f"O campo {field_name} tem de estar em base64 valido.",
            )

        if expected_size is not None and len(decoded) != expected_size:
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_SEND,
                f"O campo {field_name} tem tamanho invalido.",
            )
        if len(decoded) < min_size:
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_SEND,
                f"O campo {field_name} nao pode estar vazio.",
            )
        if max_size is not None and len(decoded) > max_size:
            return self._make_response(
                request,
                STATUS_ERROR,
                ACTION_SEND,
                f"O campo {field_name} excede o tamanho maximo permitido.",
            )
        return None

    def _require_authenticated_username(
        self,
        connection: ClientConnection,
        request: dict[str, Any],
        action: str,
    ) -> tuple[str | None, dict[str, Any] | None]:
        session_username = connection.authenticated_username
        if session_username is None:
            return None, self._authentication_required_response(request, action)
        return session_username, None

    def _parse_send_request(
        self,
        request: dict[str, Any],
        payload: dict[str, Any],
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        validation_error = self._validate_payload_fields(
            request,
            ACTION_SEND,
            payload,
            required_fields={"to"},
            optional_fields={"message", "payload", "metadata"},
        )
        if validation_error is not None:
            return None, validation_error

        recipient = self._clean_username(payload.get("to"))
        if not recipient:
            return None, self._make_response(
                request,
                STATUS_ERROR,
                ACTION_SEND,
                username_policy_message(),
            )

        has_legacy_message = "message" in payload
        has_opaque_payload = "payload" in payload
        if has_legacy_message == has_opaque_payload:
            return None, self._make_response(
                request,
                STATUS_ERROR,
                ACTION_SEND,
                "O payload de /send deve incluir exatamente um de: message ou payload.",
            )

        metadata = payload.get("metadata", {})
        metadata_error = self._validate_metadata(request, ACTION_SEND, metadata)
        if metadata_error is not None:
            return None, metadata_error

        if has_legacy_message:
            return None, self._make_response(
                request,
                STATUS_ERROR,
                ACTION_SEND,
                "Novos envios devem usar payload E2EE; plaintext legacy nao e aceite pelo servidor.",
            )
        else:
            opaque_payload, payload_error = self._normalize_opaque_payload(
                request,
                payload.get("payload"),
            )
            if payload_error is not None:
                return None, payload_error

        return {
            "recipient": recipient,
            "payload": opaque_payload,
            "metadata": dict(metadata),
        }, None

    def _normalize_opaque_payload(
        self,
        request: dict[str, Any],
        raw_payload: Any,
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        if not isinstance(raw_payload, dict):
            return None, self._make_response(
                request,
                STATUS_ERROR,
                ACTION_SEND,
                "O campo payload de /send tem de ser um objeto JSON.",
            )
        unexpected_fields = sorted(field for field in raw_payload if field not in {"content_type", "body"})
        if unexpected_fields:
            unexpected = ", ".join(str(field) for field in unexpected_fields[:5])
            return None, self._make_response(
                request,
                STATUS_ERROR,
                ACTION_SEND,
                f"O payload da mensagem contem campos inesperados: {unexpected}.",
            )

        content_type = self._clean_string(raw_payload.get("content_type"))
        if not content_type:
            return None, self._make_response(
                request,
                STATUS_ERROR,
                ACTION_SEND,
                "O payload da mensagem tem de incluir um content_type valido.",
            )
        if len(content_type) > MAX_CONTENT_TYPE_LENGTH:
            return None, self._make_response(
                request,
                STATUS_ERROR,
                ACTION_SEND,
                "O content_type da mensagem excede o tamanho maximo permitido.",
            )
        if content_type != E2EE_MESSAGE_CONTENT_TYPE:
            return None, self._make_response(
                request,
                STATUS_ERROR,
                ACTION_SEND,
                "Novos envios devem usar payload E2EE application/e2ee+json.",
            )

        if "body" not in raw_payload:
            return None, self._make_response(
                request,
                STATUS_ERROR,
                ACTION_SEND,
                "O payload da mensagem tem de incluir o campo body.",
            )

        body = raw_payload.get("body")
        if not isinstance(body, dict):
            return None, self._make_response(
                request,
                STATUS_ERROR,
                ACTION_SEND,
                "O body E2EE da mensagem tem de ser um objeto JSON.",
            )
        body_error = self._validate_e2ee_body(request, body)
        if body_error is not None:
            return None, body_error

        # O servidor valida formato e limites, mas não interpreta o conteúdo E2EE.
        normalized_payload = {
            "content_type": content_type,
            "body": dict(body),
        }

        return normalized_payload, None

    def _build_message_envelope(
        self,
        *,
        sender: str,
        recipient: str,
        opaque_payload: dict[str, Any],
        metadata: dict[str, Any],
    ) -> dict[str, Any]:
        # A identidade do remetente deriva sempre da sessão autenticada.
        return {
            "sender": sender,
            "recipient": recipient,
            "payload": opaque_payload,
            "metadata": metadata,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": MESSAGE_STATUS_PENDING,
        }

    @staticmethod
    def _clear_pending_login(connection: ClientConnection) -> None:
        connection.pending_login = None

    def _unregister_online_user(self, connection: ClientConnection) -> None:
        username = connection.authenticated_username
        if username is None:
            self._clear_pending_login(connection)
            return

        with self.online_lock:
            active_connection = self.online_users.get(username)
            if active_connection is connection:
                self.online_users.pop(username, None)
                print(f"[SERVER] User '{username}' went offline", flush=True)

        connection.authenticated_username = None
        self._clear_pending_login(connection)

    @staticmethod
    def _clean_string(value: Any) -> str:
        return clean_string(value)

    @classmethod
    def _clean_username(cls, value: Any) -> str:
        return normalize_username(value)

    @staticmethod
    def _safe_action_name(value: Any) -> str:
        if is_safe_token(value, max_length=MAX_ACTION_LENGTH):
            return clean_string(value)
        return "unknown"


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Servidor TCP do chat academico.")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Host onde o servidor escuta.")
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help="Porto TCP onde o servidor escuta.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_arguments()
    server = ChatServer(host=args.host, port=args.port)
    server.start()


if __name__ == "__main__":
    main()
