"""
Cliente CLI do sistema de conversação seguro.

Gere a ligação TLS ao servidor, registo e autenticação challenge-response,
cifra ponta-a-ponta das mensagens, consulta da inbox e confirmação de
entrega após processamento local.
"""

import argparse
import queue
import secrets
import socket
import sys
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parents[1]))

from client.commands import CommandError, HELP_TEXT, ParsedCommand, parse_command
from client.key_manager import IdentityBundle, KeyManager
from common.constants import (
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
    MAX_TEXT_MESSAGE_CHARS,
    MESSAGE_TYPE_EVENT,
    MESSAGE_TYPE_REQUEST,
    MESSAGE_TYPE_RESPONSE,
    SESSION_HEADER_TYPE_EXISTING,
    SESSION_HEADER_TYPE_INIT,
    SESSION_INIT_MODE_REPLY_PREKEY,
    SESSION_INIT_MODE_STATIC,
    SESSION_MAX_MESSAGES,
    SESSION_MAX_SKIP,
    SESSION_TTL_SECONDS,
    STATUS_ERROR,
    STATUS_OK,
    TRUSTED_SERVER_CERT_FILE,
    TRUSTED_SERVER_FINGERPRINT_FILE,
)
from common.crypto_utils import (
    CryptoError,
    canonical_json_bytes,
    decode_base64_to_bytes,
    decrypt_chacha20_poly1305,
    derive_hkdf_key,
    derive_x25519_shared_key,
    encode_bytes_to_base64,
    encrypt_chacha20_poly1305,
    generate_x25519_keypair,
    load_public_key_from_base64,
    load_x25519_public_key_from_base64,
    load_x25519_private_key_from_pem,
    serialize_x25519_private_key_to_pem,
    serialize_x25519_public_key_to_base64,
    verify_signature,
)
from common.protocol import (
    ConnectionClosedError,
    ProtocolError,
    receive_message,
    send_message,
)
from common.tls_utils import TLSError, connect_tls_socket
from common.validation import clean_string, normalize_username, username_policy_message


class ChatClient:
    def __init__(self, host: str, port: int, key_manager: KeyManager | None = None):
        self.host = host
        self.port = port
        self.sock: socket.socket | None = None
        self.running = False
        self.exiting = False
        self.response_queue: queue.Queue[dict[str, Any] | None] = queue.Queue()
        self.pending_responses: dict[str, dict[str, Any]] = {}
        self.pending_lock = threading.Lock()
        self.receiver_thread: threading.Thread | None = None
        self.current_user: str | None = None
        self.key_manager = key_manager or KeyManager()
        self.tls_bootstrapped = False
        self.server_fingerprint = ""

    def connect(self) -> None:
        try:
            # O protocolo aplicacional só é usado depois do canal TLS estar estabelecido.
            self.sock, self.tls_bootstrapped, self.server_fingerprint = connect_tls_socket(
                self.host,
                self.port,
                trusted_cert_path=TRUSTED_SERVER_CERT_FILE,
                fingerprint_path=TRUSTED_SERVER_FINGERPRINT_FILE,
            )
        except (TLSError, OSError) as exc:
            raise ConnectionError(str(exc)) from exc

        self.running = True
        self.exiting = False
        self.receiver_thread = threading.Thread(target=self._receive_loop)
        self.receiver_thread.start()

    def run(self) -> None:
        self.connect()
        if self.tls_bootstrapped:
            print(
                "[TLS] Primeira confianca do servidor criada por TOFU em "
                f"{TRUSTED_SERVER_CERT_FILE}."
            )
        print(f"[TLS] Servidor validado com fingerprint {self.server_fingerprint}.")
        print(f"Ligado ao servidor em {self.host}:{self.port}")
        print("Use /help para ver os comandos disponiveis.")

        try:
            while self.running:
                try:
                    raw_command = input("> ")
                except EOFError:
                    raw_command = "/exit"
                except KeyboardInterrupt:
                    print()
                    raw_command = "/exit"

                try:
                    command = parse_command(raw_command)
                except CommandError as exc:
                    print(f"Erro: {exc}")
                    continue

                if command.local_only:
                    self._handle_local_command(command)
                    continue

                try:
                    response = self.send_request(command)
                except ConnectionError as exc:
                    print(f"Erro de ligacao: {exc}")
                    break

                self._display_response(command, response)

                if command.name == ACTION_EXIT:
                    break
        finally:
            self.close()

    def send_request(self, command: ParsedCommand) -> dict[str, Any]:
        if command.name == ACTION_REGISTER:
            return self._register_with_identity(command)
        if command.name == ACTION_LOGIN:
            return self._login_with_challenge_response(command)
        if command.name == ACTION_SEND:
            return self._send_encrypted_message(command)
        return self._send_action(command.name, command.payload)

    def close(self) -> None:
        self.running = False
        self.current_user = None
        if self.sock is not None:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

        if (
            self.receiver_thread is not None
            and self.receiver_thread.is_alive()
            and threading.current_thread() is not self.receiver_thread
        ):
            self.receiver_thread.join(timeout=1)

    def _register_with_identity(self, command: ParsedCommand) -> dict[str, Any]:
        username = self._clean_username(command.payload.get("username"))
        if not username:
            return self._local_error_response(ACTION_REGISTER, username_policy_message())

        try:
            # O registo gera material criptográfico local e exporta apenas public keys.
            identity = self.key_manager.ensure_registration_identity(username)
        except CryptoError as exc:
            return self._local_error_response(ACTION_REGISTER, str(exc))

        try:
            response = self._send_action(
                ACTION_REGISTER,
                {
                    "username": username,
                    "public_keys": {
                        "ed25519": identity.ed25519_public_key,
                        "x25519": identity.x25519_public_key,
                    },
                },
            )
        except ConnectionError:
            self._cleanup_created_identity(username, identity)
            raise

        if response.get("status") == STATUS_OK:
            return response

        cleanup_error = self._cleanup_created_identity(username, identity)
        if cleanup_error is not None:
            return self._local_error_response(
                ACTION_REGISTER,
                f"{response.get('message', '')} Falhou tambem a limpeza local: {cleanup_error}",
            )
        return response

    def _login_with_challenge_response(self, command: ParsedCommand) -> dict[str, Any]:
        username = self._clean_username(command.payload.get("username"))
        if not username:
            return self._local_error_response(ACTION_LOGIN, username_policy_message())

        try:
            identity = self.key_manager.ensure_login_identity(username)
        except CryptoError as exc:
            return self._local_error_response(ACTION_LOGIN, str(exc))

        init_response = self._send_action(ACTION_LOGIN_INIT, {"username": username})
        if init_response.get("status") != STATUS_OK:
            return self._alias_response(init_response, ACTION_LOGIN)

        nonce_b64 = init_response.get("data", {}).get("nonce")
        try:
            nonce = decode_base64_to_bytes(nonce_b64)
            if len(nonce) != 32:
                raise CryptoError("O nonce recebido do servidor tem tamanho invalido.")
            # A posse da identidade Ed25519 é provada assinando o nonce do servidor.
            signature = self.key_manager.sign_login_challenge(username, nonce)
        except CryptoError as exc:
            self._cancel_pending_login(username)
            return self._local_error_response(ACTION_LOGIN, str(exc))

        finish_response = self._send_action(
            ACTION_LOGIN_FINISH,
            {
                "username": username,
                "signature": encode_bytes_to_base64(signature),
                "ed25519_public_key": identity.ed25519_public_key,
                "x25519_public_key": identity.x25519_public_key,
            },
        )
        return self._alias_response(finish_response, ACTION_LOGIN)

    def _send_encrypted_message(self, command: ParsedCommand) -> dict[str, Any]:
        sender = self.current_user
        if not sender:
            return self._local_error_response(
                ACTION_SEND,
                "Tem de fazer login antes de usar este comando.",
            )

        recipient = self._clean_username(command.payload.get("to"))
        plaintext = command.payload.get("message")
        if not recipient:
            return self._local_error_response(
                ACTION_SEND,
                username_policy_message(),
            )
        if not isinstance(plaintext, str) or not plaintext.strip():
            return self._local_error_response(
                ACTION_SEND,
                "A mensagem nao pode estar vazia.",
            )
        if len(plaintext.strip()) > MAX_TEXT_MESSAGE_CHARS:
            return self._local_error_response(
                ACTION_SEND,
                f"A mensagem nao pode exceder {MAX_TEXT_MESSAGE_CHARS} caracteres.",
            )

        try:
            recipient_public_keys = self._fetch_user_public_keys(recipient)
            # A cifra E2EE é realizada localmente antes de qualquer envio ao servidor.
            encrypted_payload, metadata = self._encrypt_message_for_recipient(
                sender=sender,
                recipient=recipient,
                plaintext=plaintext.strip(),
                recipient_public_keys=recipient_public_keys,
            )
        except CryptoError as exc:
            return self._local_error_response(ACTION_SEND, str(exc))

        return self._send_action(
            ACTION_SEND,
            {
                "to": recipient,
                "payload": encrypted_payload,
                "metadata": metadata,
            },
        )

    def _encrypt_message_for_recipient(
        self,
        *,
        sender: str,
        recipient: str,
        plaintext: str,
        recipient_public_keys: dict[str, str],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        inner_content_type = DEFAULT_MESSAGE_CONTENT_TYPE
        session_store = self.key_manager.load_session_store(sender)
        outbound_sessions = session_store["outbound_sessions"]
        session_record = outbound_sessions.get(recipient)

        if not self._is_outbound_session_usable(session_record):
            session_record = self._create_outbound_session(
                sender=sender,
                recipient=recipient,
                recipient_public_keys=recipient_public_keys,
                session_store=session_store,
            )

        message_counter = session_record["next_counter"]
        message_key, next_chain_key = self._derive_message_key_from_chain(
            chain_key_b64=session_record["chain_key"],
            counter=message_counter,
        )
        reply_prekey = self._create_reply_prekey_offer(
            sender=sender,
            recipient=recipient,
            session_store=session_store,
        )

        session_header = {
            "type": SESSION_HEADER_TYPE_EXISTING,
        }
        if message_counter == 0:
            session_header = {
                "type": SESSION_HEADER_TYPE_INIT,
                "init_mode": session_record["init_mode"],
                "session_public_key": session_record["session_public_key"],
            }
            if session_record.get("peer_reply_prekey_id"):
                session_header["peer_reply_prekey_id"] = session_record["peer_reply_prekey_id"]

        nonce = secrets.token_bytes(12)
        body = {
            "version": E2EE_SESSION_MESSAGE_VERSION,
            "encryption": E2EE_SESSION_ENCRYPTION_SUITE,
            "inner_content_type": inner_content_type,
            "session_id": session_record["session_id"],
            "counter": message_counter,
            "session_header": session_header,
            "reply_prekey": reply_prekey,
        }
        aad = self._build_session_aad(
            sender=sender,
            recipient=recipient,
            body=body,
        )
        ciphertext = encrypt_chacha20_poly1305(
            message_key,
            nonce,
            plaintext.encode("utf-8"),
            aad,
        )
        body["nonce"] = encode_bytes_to_base64(nonce)
        body["ciphertext"] = encode_bytes_to_base64(ciphertext)

        signature = self.key_manager.sign_message(
            sender,
            self._build_session_signature_bytes(
                sender=sender,
                recipient=recipient,
                body=body,
            ),
        )
        body["signature_algorithm"] = E2EE_SIGNATURE_ALGORITHM
        body["signature"] = encode_bytes_to_base64(signature)

        session_record["chain_key"] = encode_bytes_to_base64(next_chain_key)
        session_record["next_counter"] = message_counter + 1
        outbound_sessions[recipient] = session_record
        self.key_manager.save_session_store(sender, session_store)

        payload = {
            "content_type": E2EE_MESSAGE_CONTENT_TYPE,
            "body": body,
        }
        metadata = {
            "encryption": E2EE_SESSION_ENCRYPTION_SUITE,
            "version": E2EE_SESSION_MESSAGE_VERSION,
            "signed": True,
            "session_id": session_record["session_id"],
            "session_counter": message_counter,
            "session_init": message_counter == 0,
            "session_init_mode": session_record["init_mode"],
        }
        return payload, metadata

    def _is_outbound_session_usable(self, session_record: Any) -> bool:
        if not isinstance(session_record, dict):
            return False

        session_id = self._clean_string(session_record.get("session_id"))
        chain_key = self._clean_string(session_record.get("chain_key"))
        session_public_key = self._clean_string(session_record.get("session_public_key"))
        if not session_id or not chain_key or not session_public_key:
            return False

        next_counter = session_record.get("next_counter")
        if not isinstance(next_counter, int) or next_counter < 0:
            return False
        if next_counter >= SESSION_MAX_MESSAGES:
            return False

        expires_at = self._parse_timestamp(session_record.get("expires_at"))
        if expires_at is None or datetime.now(timezone.utc) >= expires_at:
            return False

        init_mode = self._clean_string(session_record.get("init_mode"))
        if init_mode not in {SESSION_INIT_MODE_STATIC, SESSION_INIT_MODE_REPLY_PREKEY}:
            return False

        return True

    def _create_outbound_session(
        self,
        *,
        sender: str,
        recipient: str,
        recipient_public_keys: dict[str, str],
        session_store: dict[str, Any],
    ) -> dict[str, Any]:
        outbound_private_key, outbound_public_key = generate_x25519_keypair()
        peer_reply_prekey = session_store["peer_reply_prekeys"].get(recipient)

        if isinstance(peer_reply_prekey, dict):
            peer_reply_prekey_id = self._clean_string(peer_reply_prekey.get("prekey_id"))
            peer_reply_prekey_public_key = self._clean_string(peer_reply_prekey.get("public_key"))
        else:
            peer_reply_prekey_id = ""
            peer_reply_prekey_public_key = ""

        if peer_reply_prekey_id and peer_reply_prekey_public_key:
            init_mode = SESSION_INIT_MODE_REPLY_PREKEY
            peer_public_key = load_x25519_public_key_from_base64(peer_reply_prekey_public_key)
            shared_secret = derive_x25519_shared_key(
                outbound_private_key,
                peer_public_key,
                info=self._build_session_root_info(
                    sender=sender,
                    recipient=recipient,
                    init_mode=init_mode,
                ),
            )
        else:
            init_mode = SESSION_INIT_MODE_STATIC
            peer_reply_prekey_id = ""
            recipient_x25519_public_key = load_x25519_public_key_from_base64(
                recipient_public_keys["x25519"]
            )
            shared_secret = derive_x25519_shared_key(
                outbound_private_key,
                recipient_x25519_public_key,
                info=self._build_session_root_info(
                    sender=sender,
                    recipient=recipient,
                    init_mode=init_mode,
                ),
            )

        session_id = secrets.token_hex(16)
        chain_key = derive_hkdf_key(
            shared_secret,
            info=self._build_session_chain_info(
                sender=sender,
                recipient=recipient,
                session_id=session_id,
            ),
        )
        created_at = self._now_iso()
        expires_at = (datetime.now(timezone.utc) + timedelta(seconds=SESSION_TTL_SECONDS)).isoformat()

        session_record = {
            "session_id": session_id,
            "chain_key": encode_bytes_to_base64(chain_key),
            "next_counter": 0,
            "created_at": created_at,
            "expires_at": expires_at,
            "init_mode": init_mode,
            "session_public_key": serialize_x25519_public_key_to_base64(outbound_public_key),
            "peer_reply_prekey_id": peer_reply_prekey_id,
        }
        session_store["outbound_sessions"][recipient] = session_record
        if init_mode == SESSION_INIT_MODE_REPLY_PREKEY:
            session_store["peer_reply_prekeys"].pop(recipient, None)
        return session_record

    def _create_reply_prekey_offer(
        self,
        *,
        sender: str,
        recipient: str,
        session_store: dict[str, Any],
    ) -> dict[str, str]:
        reply_private_key, reply_public_key = generate_x25519_keypair()
        prekey_id = secrets.token_hex(12)
        session_store["advertised_reply_prekeys"][prekey_id] = {
            "peer": recipient,
            "public_key": serialize_x25519_public_key_to_base64(reply_public_key),
            "private_key_pem_b64": encode_bytes_to_base64(
                serialize_x25519_private_key_to_pem(reply_private_key)
            ),
            "created_at": self._now_iso(),
        }
        self._prune_advertised_reply_prekeys(session_store=session_store, peer=recipient)
        return {
            "prekey_id": prekey_id,
            "public_key": serialize_x25519_public_key_to_base64(reply_public_key),
        }

    def _derive_message_key_from_chain(
        self,
        *,
        chain_key_b64: str,
        counter: int,
    ) -> tuple[bytes, bytes]:
        chain_key = decode_base64_to_bytes(chain_key_b64)
        message_key = derive_hkdf_key(
            chain_key,
            info=canonical_json_bytes(
                {
                    "type": "ssi-chat-session-message-key",
                    "counter": counter,
                }
            ),
        )
        next_chain_key = derive_hkdf_key(
            chain_key,
            info=canonical_json_bytes(
                {
                    "type": "ssi-chat-session-chain-advance",
                    "counter": counter,
                }
            ),
        )
        return message_key, next_chain_key

    def _cancel_pending_login(self, username: str) -> None:
        try:
            self._send_action(ACTION_LOGIN_CANCEL, {"username": username})
        except ConnectionError:
            pass

    def _send_action(self, action: str, payload: dict[str, Any]) -> dict[str, Any]:
        if not self.running or self.sock is None:
            raise ConnectionError("O cliente nao esta ligado ao servidor.")

        request_id = uuid.uuid4().hex
        request_payload = {
            "type": MESSAGE_TYPE_REQUEST,
            "request_id": request_id,
            "action": action,
            "payload": payload,
        }
        if action == ACTION_EXIT:
            self.exiting = True

        try:
            send_message(self.sock, request_payload)
        except (OSError, ProtocolError) as exc:
            raise ConnectionError(f"Falha ao enviar pedido ao servidor: {exc}") from exc

        return self._wait_for_response(request_id)

    def _receive_loop(self) -> None:
        try:
            while self.running and self.sock is not None:
                message = receive_message(self.sock)
                message_type = message.get("type")

                if message_type == MESSAGE_TYPE_RESPONSE:
                    self.response_queue.put(message)
                    continue

                if message_type == MESSAGE_TYPE_EVENT:
                    self._display_event(message)
                    continue

                print("\n[WARN] Mensagem desconhecida recebida do servidor.")
                print("> ", end="", flush=True)
        except (ConnectionClosedError, ProtocolError, OSError) as exc:
            if self.running and not self.exiting:
                print(f"\n[INFO] Ligacao ao servidor terminada: {exc}")
                print("> ", end="", flush=True)
        finally:
            self.running = False
            self.response_queue.put(None)

    def _wait_for_response(self, request_id: str) -> dict[str, Any]:
        with self.pending_lock:
            cached_response = self.pending_responses.pop(request_id, None)
        if cached_response is not None:
            return cached_response

        while self.running:
            response = self.response_queue.get()
            if response is None:
                raise ConnectionError("A ligacao ao servidor foi encerrada.")

            response_id = response.get("request_id")
            if response_id == request_id:
                return response

            with self.pending_lock:
                if response_id is not None:
                    self.pending_responses[response_id] = response

        raise ConnectionError("A ligacao ao servidor foi encerrada.")

    def _handle_local_command(self, command: ParsedCommand) -> None:
        if command.name == "help":
            print(HELP_TEXT.rstrip())

    def _display_response(self, command: ParsedCommand, response: dict[str, Any]) -> None:
        status = response.get("status")
        message = response.get("message", "")
        data = response.get("data", {})

        if status != STATUS_OK:
            print(f"Erro: {message}")
            return

        if command.name == ACTION_LOGIN:
            self.current_user = data.get("username")
            pending_count = data.get("pending_messages", 0)
            print(message)
            print(f"Mensagens pendentes: {pending_count}. Use /inbox para consultar.")
            return

        if command.name == ACTION_LIST_CONTACTS:
            contacts = data.get("contacts", [])
            print("Contactos:")
            if not contacts:
                print("  (sem contactos)")
            else:
                for contact in contacts:
                    print(f"  - {contact}")
            return

        if command.name == ACTION_ONLINE:
            online_users = data.get("online_users", [])
            print("Utilizadores online:")
            if not online_users:
                print("  (ninguem online)")
            else:
                for username in online_users:
                    print(f"  - {username}")
            return

        if command.name == ACTION_INBOX:
            self._display_inbox_messages(data)
            return

        if command.name == ACTION_EXIT:
            print(message)
            return

        print(message)

    def _display_event(self, message: dict[str, Any]) -> None:
        event_name = message.get("event")
        if event_name == EVENT_INCOMING_MESSAGE:
            sender = message.get("data", {}).get("sender", "desconhecido")
            timestamp = message.get("data", {}).get("timestamp", "sem_timestamp")
            print(
                f"\n[INFO] Nova mensagem de {sender} ({timestamp}). "
                "Use /inbox para a consultar."
            )
            print("> ", end="", flush=True)
            return

        print(f"\n[INFO] Evento recebido: {message.get('message', event_name)}")
        print("> ", end="", flush=True)

    def _display_inbox_messages(self, data: dict[str, Any]) -> None:
        messages = data.get("messages", [])
        if not isinstance(messages, list):
            print("Erro: a resposta do servidor para /inbox esta malformada.")
            return

        if not messages:
            print("Inbox vazia.")
            return

        print("Mensagens recebidas:")
        sender_key_cache: dict[str, dict[str, str]] = {}
        ack_message_ids: list[str] = []
        failed_messages = 0

        # A inbox é descifrada localmente; só mensagens processadas entram no ack.
        for raw_entry in messages:
            if not isinstance(raw_entry, dict):
                print("  [sem_timestamp] desconhecido: [entrada de inbox malformada]")
                failed_messages += 1
                continue

            timestamp = raw_entry.get("timestamp", "sem_timestamp")
            sender = raw_entry.get("sender", "desconhecido")
            content, processed_successfully = self._process_inbox_message(
                raw_entry,
                sender_key_cache,
            )

            if processed_successfully:
                message_id = self._clean_string(raw_entry.get("message_id"))
                if message_id:
                    ack_message_ids.append(message_id)
                else:
                    processed_successfully = False
                    content = f"{content} [sem message_id; nao confirmada]"

            if not processed_successfully:
                failed_messages += 1

            print(f"  [{timestamp}] {sender}: {content}")

        if ack_message_ids:
            self._acknowledge_inbox_messages(ack_message_ids)

        if failed_messages:
            print(
                f"{failed_messages} mensagem(ns) ficaram pendentes por falha de processamento "
                "ou formato nao suportado."
            )

    def _process_inbox_message(
        self,
        entry: dict[str, Any],
        sender_key_cache: dict[str, dict[str, str]],
    ) -> tuple[str, bool]:
        payload = entry.get("payload", {})
        if not isinstance(payload, dict):
            return "[payload malformado]", False

        content_type = payload.get("content_type")
        body = payload.get("body")

        if content_type == DEFAULT_MESSAGE_CONTENT_TYPE and isinstance(body, str):
            return body, True

        if content_type == DEFAULT_MESSAGE_CONTENT_TYPE:
            return "[payload text/plain malformado]", False

        if content_type == E2EE_MESSAGE_CONTENT_TYPE:
            try:
                return self._decrypt_inbox_message(entry, sender_key_cache), True
            except (CryptoError, ConnectionError) as exc:
                return f"[erro ao descifrar: {exc}]", False

        if isinstance(content_type, str) and content_type:
            return f"[payload nao suportado: {content_type}]", False

        return "[payload desconhecido]", False

    def _acknowledge_inbox_messages(self, message_ids: list[str]) -> None:
        unique_message_ids: list[str] = []
        seen_message_ids: set[str] = set()
        for message_id in message_ids:
            cleaned_message_id = self._clean_string(message_id)
            if not cleaned_message_id or cleaned_message_id in seen_message_ids:
                continue
            seen_message_ids.add(cleaned_message_id)
            unique_message_ids.append(cleaned_message_id)

        if not unique_message_ids:
            return

        try:
            response = self._send_action(
                ACTION_ACK_INBOX,
                {"message_ids": unique_message_ids},
            )
        except ConnectionError as exc:
            print(f"[WARN] Falhou o ack interno da inbox: {exc}")
            return

        if response.get("status") != STATUS_OK:
            print(f"[WARN] O servidor rejeitou o ack da inbox: {response.get('message', '')}")
            return

        data = response.get("data", {})
        acknowledged_count = data.get("acknowledged_count", 0)
        already_delivered_count = data.get("already_delivered_count", 0)
        unknown_count = data.get("unknown_count", 0)

        print(
            "Confirmacao de entrega enviada ao servidor para "
            f"{acknowledged_count + already_delivered_count} mensagem(ns)."
        )
        if unknown_count:
            print(f"[WARN] O servidor nao reconheceu {unknown_count} message_id(s) no ack.")

    def _decrypt_inbox_message(
        self,
        entry: dict[str, Any],
        sender_key_cache: dict[str, dict[str, str]],
    ) -> str:
        if not self.current_user:
            raise CryptoError("Nao existe utilizador autenticado para descifrar a inbox.")

        payload = entry.get("payload", {})
        if not isinstance(payload, dict):
            raise CryptoError("O payload recebido nao e um objeto JSON valido.")

        body = payload.get("body")
        if not isinstance(body, dict):
            raise CryptoError("O body da mensagem cifrada esta malformado.")

        sender = self._clean_username(entry.get("sender"))
        recipient = self._clean_username(entry.get("recipient")) or self.current_user
        version = body.get("version")
        if version == E2EE_SESSION_MESSAGE_VERSION:
            return self._decrypt_session_message(
                entry=entry,
                body=body,
                sender=sender,
                recipient=recipient,
                sender_key_cache=sender_key_cache,
            )
        if version == E2EE_MESSAGE_VERSION:
            return self._decrypt_legacy_e2ee_message(
                body=body,
                sender=sender,
                recipient=recipient,
                sender_key_cache=sender_key_cache,
            )
        raise CryptoError("A versao da mensagem E2EE nao e suportada.")

    def _decrypt_legacy_e2ee_message(
        self,
        *,
        body: dict[str, Any],
        sender: str,
        recipient: str,
        sender_key_cache: dict[str, dict[str, str]],
    ) -> str:
        encryption = self._clean_string(body.get("encryption"))
        inner_content_type = self._clean_string(body.get("inner_content_type"))
        if encryption != E2EE_ENCRYPTION_SUITE:
            raise CryptoError("O algoritmo de cifragem da mensagem nao e suportado.")
        if inner_content_type != DEFAULT_MESSAGE_CONTENT_TYPE:
            raise CryptoError("O content_type interno da mensagem nao e suportado.")

        ephemeral_public_key_b64 = self._clean_string(body.get("ephemeral_public_key"))
        nonce_b64 = self._clean_string(body.get("nonce"))
        ciphertext_b64 = self._clean_string(body.get("ciphertext"))
        signature_algorithm = self._clean_string(body.get("signature_algorithm"))
        signature_b64 = self._clean_string(body.get("signature"))
        if not ephemeral_public_key_b64 or not nonce_b64 or not ciphertext_b64:
            raise CryptoError("A mensagem cifrada nao contem todos os campos obrigatorios.")
        if signature_algorithm != E2EE_SIGNATURE_ALGORITHM or not signature_b64:
            raise CryptoError("A mensagem E2EE nao inclui uma assinatura Ed25519 suportada.")

        sender_public_keys = sender_key_cache.get(sender)
        if sender_public_keys is None:
            sender_public_keys = self._fetch_user_public_keys(sender)
            sender_key_cache[sender] = sender_public_keys

        sender_public_key = load_public_key_from_base64(sender_public_keys["ed25519"])
        signature_payload = self._build_e2ee_signature_bytes(
            sender=sender,
            recipient=recipient,
            body=body,
        )
        signature = decode_base64_to_bytes(signature_b64)
        if not verify_signature(sender_public_key, signature_payload, signature):
            raise CryptoError("A assinatura Ed25519 da mensagem e invalida.")

        recipient_private_key = self.key_manager.load_x25519_private_key(self.current_user)
        ephemeral_public_key = load_x25519_public_key_from_base64(ephemeral_public_key_b64)
        hkdf_info = self._build_e2ee_hkdf_info(
            sender=sender,
            recipient=recipient,
            inner_content_type=inner_content_type,
        )
        symmetric_key = derive_x25519_shared_key(
            recipient_private_key,
            ephemeral_public_key,
            info=hkdf_info,
        )

        nonce = decode_base64_to_bytes(nonce_b64)
        ciphertext = decode_base64_to_bytes(ciphertext_b64)
        plaintext = decrypt_chacha20_poly1305(
            symmetric_key,
            nonce,
            ciphertext,
            self._build_e2ee_aad(
                sender=sender,
                recipient=recipient,
                inner_content_type=inner_content_type,
            ),
        )

        try:
            return plaintext.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CryptoError("O plaintext da mensagem nao esta em UTF-8 valido.") from exc

    def _decrypt_session_message(
        self,
        *,
        entry: dict[str, Any],
        body: dict[str, Any],
        sender: str,
        recipient: str,
        sender_key_cache: dict[str, dict[str, str]],
    ) -> str:
        if not self.current_user:
            raise CryptoError("Nao existe utilizador autenticado para descifrar a inbox.")

        encryption = self._clean_string(body.get("encryption"))
        inner_content_type = self._clean_string(body.get("inner_content_type"))
        session_id = self._clean_string(body.get("session_id"))
        nonce_b64 = self._clean_string(body.get("nonce"))
        ciphertext_b64 = self._clean_string(body.get("ciphertext"))
        signature_algorithm = self._clean_string(body.get("signature_algorithm"))
        signature_b64 = self._clean_string(body.get("signature"))
        session_header = body.get("session_header")
        reply_prekey = body.get("reply_prekey")
        counter = body.get("counter")

        if encryption != E2EE_SESSION_ENCRYPTION_SUITE:
            raise CryptoError("O algoritmo de cifragem da sessao nao e suportado.")
        if inner_content_type != DEFAULT_MESSAGE_CONTENT_TYPE:
            raise CryptoError("O content_type interno da mensagem nao e suportado.")
        if not session_id or not isinstance(counter, int) or counter < 0:
            raise CryptoError("A mensagem de sessao nao inclui identificadores validos.")
        if not isinstance(session_header, dict):
            raise CryptoError("O cabecalho de sessao recebido esta malformado.")
        if not nonce_b64 or not ciphertext_b64:
            raise CryptoError("A mensagem de sessao nao contem todos os campos obrigatorios.")
        if signature_algorithm != E2EE_SIGNATURE_ALGORITHM or not signature_b64:
            raise CryptoError("A mensagem de sessao nao inclui uma assinatura Ed25519 suportada.")

        sender_public_keys = sender_key_cache.get(sender)
        if sender_public_keys is None:
            sender_public_keys = self._fetch_user_public_keys(sender)
            sender_key_cache[sender] = sender_public_keys

        sender_public_key = load_public_key_from_base64(sender_public_keys["ed25519"])
        signature = decode_base64_to_bytes(signature_b64)
        if not verify_signature(
            sender_public_key,
            self._build_session_signature_bytes(sender=sender, recipient=recipient, body=body),
            signature,
        ):
            raise CryptoError("A assinatura Ed25519 da mensagem de sessao e invalida.")

        session_store = self.key_manager.load_session_store(self.current_user)
        peer_sessions = session_store["inbound_sessions"].setdefault(sender, {})
        session_record = peer_sessions.get(session_id)
        if session_record is None:
            session_record = self._initialize_inbound_session(
                sender=sender,
                recipient=recipient,
                sender_public_keys=sender_public_keys,
                body=body,
                session_store=session_store,
            )
            peer_sessions[session_id] = session_record

        next_counter = session_record.get("next_counter", 0)
        if counter < next_counter:
            raise CryptoError("A mensagem de sessao e antiga ou repetida.")
        if counter - next_counter > SESSION_MAX_SKIP:
            raise CryptoError("A mensagem de sessao salta demasiado o contador esperado.")

        current_chain_key_b64 = session_record["chain_key"]
        message_key = b""
        advanced_chain_key = b""
        current_counter = next_counter
        while current_counter <= counter:
            message_key, advanced_chain_key = self._derive_message_key_from_chain(
                chain_key_b64=current_chain_key_b64,
                counter=current_counter,
            )
            current_chain_key_b64 = encode_bytes_to_base64(advanced_chain_key)
            current_counter += 1

        plaintext = decrypt_chacha20_poly1305(
            message_key,
            decode_base64_to_bytes(nonce_b64),
            decode_base64_to_bytes(ciphertext_b64),
            self._build_session_aad(
                sender=sender,
                recipient=recipient,
                body=body,
            ),
        )

        session_record["chain_key"] = current_chain_key_b64
        session_record["next_counter"] = counter + 1
        peer_sessions[session_id] = session_record
        self._remember_peer_reply_prekey(
            session_store=session_store,
            peer=sender,
            reply_prekey=reply_prekey,
        )
        self.key_manager.save_session_store(self.current_user, session_store)

        try:
            return plaintext.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CryptoError("O plaintext da mensagem nao esta em UTF-8 valido.") from exc

    def _fetch_user_public_keys(self, username: str) -> dict[str, str]:
        response = self._send_action(ACTION_GET_USER_KEYS, {"username": username})
        if response.get("status") != STATUS_OK:
            raise CryptoError(response.get("message", "Falhou a obtencao das chaves publicas."))

        data = response.get("data", {})
        public_keys = data.get("public_keys")
        if not isinstance(public_keys, dict):
            raise CryptoError("O servidor devolveu uma estrutura de chaves publicas invalida.")

        ed25519_public_key = self._clean_string(public_keys.get("ed25519"))
        x25519_public_key = self._clean_string(public_keys.get("x25519"))
        if not ed25519_public_key or not x25519_public_key:
            raise CryptoError("O servidor devolveu chaves publicas incompletas.")

        return {
            "ed25519": ed25519_public_key,
            "x25519": x25519_public_key,
        }

    def _initialize_inbound_session(
        self,
        *,
        sender: str,
        recipient: str,
        sender_public_keys: dict[str, str],
        body: dict[str, Any],
        session_store: dict[str, Any],
    ) -> dict[str, Any]:
        session_header = body.get("session_header", {})
        header_type = self._clean_string(session_header.get("type"))
        if header_type != SESSION_HEADER_TYPE_INIT:
            raise CryptoError("A mensagem refere uma sessao desconhecida sem cabecalho de inicializacao.")

        init_mode = self._clean_string(session_header.get("init_mode"))
        session_public_key_b64 = self._clean_string(session_header.get("session_public_key"))
        if init_mode not in {SESSION_INIT_MODE_STATIC, SESSION_INIT_MODE_REPLY_PREKEY}:
            raise CryptoError("O modo de inicializacao da sessao nao e suportado.")
        if not session_public_key_b64:
            raise CryptoError("Falta a chave publica efemera da sessao.")

        peer_session_public_key = load_x25519_public_key_from_base64(session_public_key_b64)
        if init_mode == SESSION_INIT_MODE_STATIC:
            private_key = self.key_manager.load_x25519_private_key(self.current_user)
        else:
            peer_reply_prekey_id = self._clean_string(session_header.get("peer_reply_prekey_id"))
            advertised_record = session_store["advertised_reply_prekeys"].get(peer_reply_prekey_id)
            if not isinstance(advertised_record, dict):
                raise CryptoError("Nao foi possivel reconstruir a sessao com a reply prekey local.")
            if self._clean_username(advertised_record.get("peer")) != sender:
                raise CryptoError("A reply prekey local nao corresponde ao remetente esperado.")
            private_key_pem_b64 = self._clean_string(advertised_record.get("private_key_pem_b64"))
            if not private_key_pem_b64:
                raise CryptoError("A reply prekey local esta corrompida.")
            private_key = load_x25519_private_key_from_pem(
                decode_base64_to_bytes(private_key_pem_b64)
            )

        shared_secret = derive_x25519_shared_key(
            private_key,
            peer_session_public_key,
            info=self._build_session_root_info(
                sender=sender,
                recipient=recipient,
                init_mode=init_mode,
            ),
        )
        session_id = self._clean_string(body.get("session_id"))
        if not session_id:
            raise CryptoError("A mensagem de sessao nao inclui um session_id valido.")

        chain_key = derive_hkdf_key(
            shared_secret,
            info=self._build_session_chain_info(
                sender=sender,
                recipient=recipient,
                session_id=session_id,
            ),
        )
        if init_mode == SESSION_INIT_MODE_REPLY_PREKEY:
            session_store["advertised_reply_prekeys"].pop(peer_reply_prekey_id, None)
        return {
            "chain_key": encode_bytes_to_base64(chain_key),
            "next_counter": 0,
            "created_at": self._now_iso(),
            "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=SESSION_TTL_SECONDS)).isoformat(),
        }

    def _remember_peer_reply_prekey(
        self,
        *,
        session_store: dict[str, Any],
        peer: str,
        reply_prekey: Any,
    ) -> None:
        if not isinstance(reply_prekey, dict):
            return

        prekey_id = self._clean_string(reply_prekey.get("prekey_id"))
        public_key = self._clean_string(reply_prekey.get("public_key"))
        if not prekey_id or not public_key:
            return

        session_store["peer_reply_prekeys"][peer] = {
            "prekey_id": prekey_id,
            "public_key": public_key,
            "received_at": self._now_iso(),
        }

    def _prune_advertised_reply_prekeys(
        self,
        *,
        session_store: dict[str, Any],
        peer: str,
        keep_latest: int = 3,
    ) -> None:
        advertised_reply_prekeys = session_store["advertised_reply_prekeys"]
        matching_records: list[tuple[str, str]] = []
        for prekey_id, record in advertised_reply_prekeys.items():
            if not isinstance(record, dict):
                continue
            if self._clean_username(record.get("peer")) != peer:
                continue
            matching_records.append((prekey_id, self._clean_string(record.get("created_at"))))

        matching_records.sort(key=lambda item: item[1], reverse=True)
        for prekey_id, _ in matching_records[keep_latest:]:
            advertised_reply_prekeys.pop(prekey_id, None)

    def _build_e2ee_hkdf_info(
        self,
        *,
        sender: str,
        recipient: str,
        inner_content_type: str,
    ) -> bytes:
        return canonical_json_bytes(
            {
                "type": "ssi-chat-e2ee-key",
                "version": E2EE_MESSAGE_VERSION,
                "encryption": E2EE_ENCRYPTION_SUITE,
                "sender": sender,
                "recipient": recipient,
                "inner_content_type": inner_content_type,
            }
        )

    def _build_session_root_info(
        self,
        *,
        sender: str,
        recipient: str,
        init_mode: str,
    ) -> bytes:
        return canonical_json_bytes(
            {
                "type": "ssi-chat-session-root",
                "version": E2EE_SESSION_MESSAGE_VERSION,
                "encryption": E2EE_SESSION_ENCRYPTION_SUITE,
                "sender": sender,
                "recipient": recipient,
                "init_mode": init_mode,
            }
        )

    def _build_session_chain_info(
        self,
        *,
        sender: str,
        recipient: str,
        session_id: str,
    ) -> bytes:
        return canonical_json_bytes(
            {
                "type": "ssi-chat-session-chain",
                "version": E2EE_SESSION_MESSAGE_VERSION,
                "sender": sender,
                "recipient": recipient,
                "session_id": session_id,
            }
        )

    def _build_e2ee_aad(
        self,
        *,
        sender: str,
        recipient: str,
        inner_content_type: str,
    ) -> bytes:
        return canonical_json_bytes(
            {
                "type": "ssi-chat-e2ee-aad",
                "version": E2EE_MESSAGE_VERSION,
                "encryption": E2EE_ENCRYPTION_SUITE,
                "sender": sender,
                "recipient": recipient,
                "inner_content_type": inner_content_type,
            }
        )

    def _build_session_aad(
        self,
        *,
        sender: str,
        recipient: str,
        body: dict[str, Any],
    ) -> bytes:
        return canonical_json_bytes(
            {
                "type": "ssi-chat-session-aad",
                "version": body.get("version"),
                "encryption": body.get("encryption"),
                "sender": sender,
                "recipient": recipient,
                "session_id": body.get("session_id"),
                "counter": body.get("counter"),
                "inner_content_type": body.get("inner_content_type"),
                "session_header": body.get("session_header"),
                "reply_prekey": body.get("reply_prekey"),
            }
        )

    def _build_e2ee_signature_bytes(
        self,
        *,
        sender: str,
        recipient: str,
        body: dict[str, Any],
    ) -> bytes:
        signable_body = {
            "version": body.get("version"),
            "encryption": body.get("encryption"),
            "inner_content_type": body.get("inner_content_type"),
            "ephemeral_public_key": body.get("ephemeral_public_key"),
            "nonce": body.get("nonce"),
            "ciphertext": body.get("ciphertext"),
        }
        return canonical_json_bytes(
            {
                "type": "ssi-chat-e2ee-signature",
                "sender": sender,
                "recipient": recipient,
                "body": signable_body,
            }
        )

    def _build_session_signature_bytes(
        self,
        *,
        sender: str,
        recipient: str,
        body: dict[str, Any],
    ) -> bytes:
        signable_body = {
            "version": body.get("version"),
            "encryption": body.get("encryption"),
            "inner_content_type": body.get("inner_content_type"),
            "session_id": body.get("session_id"),
            "counter": body.get("counter"),
            "session_header": body.get("session_header"),
            "reply_prekey": body.get("reply_prekey"),
            "nonce": body.get("nonce"),
            "ciphertext": body.get("ciphertext"),
        }
        return canonical_json_bytes(
            {
                "type": "ssi-chat-session-signature",
                "sender": sender,
                "recipient": recipient,
                "body": signable_body,
            }
        )

    def _cleanup_created_identity(
        self,
        username: str,
        identity: IdentityBundle,
    ) -> str | None:
        if not identity.created_any:
            return None

        try:
            self.key_manager.delete_identity(
                username,
                remove_ed25519=identity.created_ed25519,
                remove_x25519=identity.created_x25519,
            )
        except CryptoError as exc:
            return str(exc)
        return None

    @staticmethod
    def _clean_username(value: Any) -> str:
        return normalize_username(value)

    @staticmethod
    def _clean_string(value: Any) -> str:
        return clean_string(value)

    @staticmethod
    def _parse_timestamp(value: Any) -> datetime | None:
        if not isinstance(value, str) or not value.strip():
            return None
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _local_error_response(action: str, message: str) -> dict[str, Any]:
        return {
            "type": MESSAGE_TYPE_RESPONSE,
            "request_id": None,
            "action": action,
            "status": STATUS_ERROR,
            "message": message,
            "data": {},
        }

    @staticmethod
    def _alias_response(response: dict[str, Any], action: str) -> dict[str, Any]:
        normalized_response = dict(response)
        normalized_response["action"] = action
        return normalized_response


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Cliente CLI do chat academico.")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Host do servidor.")
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help="Porto TCP do servidor.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_arguments()
    client = ChatClient(host=args.host, port=args.port)

    try:
        client.run()
    except ConnectionRefusedError:
        print(f"Nao foi possivel ligar ao servidor em {args.host}:{args.port}.")
    except ConnectionError as exc:
        print(f"Erro TLS/ligacao: {exc}")


if __name__ == "__main__":
    main()
