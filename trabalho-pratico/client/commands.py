"""
Parser dos comandos da interface de linha de comandos.

Traduz entrada textual do utilizador para ações do protocolo sem
executar lógica de rede ou criptografia.
"""

from dataclasses import dataclass, field

from common.constants import (
    ACTION_ADD_CONTACT,
    ACTION_EXIT,
    ACTION_INBOX,
    ACTION_LIST_CONTACTS,
    ACTION_LOGIN,
    ACTION_ONLINE,
    ACTION_REGISTER,
    ACTION_SEND,
)


class CommandError(Exception):
    """Erro de sintaxe ou uso de comando CLI."""


@dataclass
class ParsedCommand:
    name: str
    payload: dict = field(default_factory=dict)
    local_only: bool = False


HELP_TEXT = """Comandos disponíveis:
/register <username>           Regista um novo utilizador
/login <username>              Faz login com um utilizador existente
/add_contact <username>        Adiciona um utilizador à lista de contactos
/list_contacts                 Lista os contactos guardados
/online                        Lista os utilizadores online
/send <username> <mensagem>    Envia uma mensagem
/inbox                         Mostra as mensagens pendentes
/help                          Mostra esta ajuda
/exit                          Fecha o cliente
"""


def parse_command(raw_command: str) -> ParsedCommand:
    command_line = raw_command.strip()
    if not command_line:
        raise CommandError("Introduza um comando.")

    if not command_line.startswith("/"):
        raise CommandError("Os comandos devem começar por '/'. Use /help para ajuda.")

    if command_line == "/help":
        return ParsedCommand(name="help", local_only=True)

    if command_line == "/exit":
        return ParsedCommand(name=ACTION_EXIT)

    parts = command_line.split(maxsplit=2)
    command = parts[0]

    if command == "/register":
        if len(parts) != 2:
            raise CommandError("Uso: /register <username>")
        return ParsedCommand(name=ACTION_REGISTER, payload={"username": parts[1]})

    if command == "/login":
        if len(parts) != 2:
            raise CommandError("Uso: /login <username>")
        return ParsedCommand(name=ACTION_LOGIN, payload={"username": parts[1]})

    if command == "/add_contact":
        if len(parts) != 2:
            raise CommandError("Uso: /add_contact <username>")
        return ParsedCommand(name=ACTION_ADD_CONTACT, payload={"username": parts[1]})

    if command == "/list_contacts":
        return ParsedCommand(name=ACTION_LIST_CONTACTS)

    if command == "/online":
        return ParsedCommand(name=ACTION_ONLINE)

    if command == "/send":
        if len(parts) < 3:
            raise CommandError("Uso: /send <username> <mensagem>")
        return ParsedCommand(
            name=ACTION_SEND,
            payload={"to": parts[1], "message": parts[2]},
        )

    if command == "/inbox":
        return ParsedCommand(name=ACTION_INBOX)

    raise CommandError("Comando desconhecido. Use /help para ver os comandos.")
