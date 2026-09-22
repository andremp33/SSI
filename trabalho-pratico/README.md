# Trabalho Prático — Segurança de Sistemas Informáticos

## Descrição

Sistema de conversação seguro em Python, com cliente CLI e servidor TCP/TLS. O projeto inclui autenticação challenge-response, cifragem ponta-a-ponta, mensagens offline e confirmação de entrega por ack.

## Requisitos

- Python 3.10+
- `cryptography`

## Instalação

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install cryptography
```

## Execução

### Servidor

```bash
cd trabalho-pratico
python3 -m server.server
```

### Cliente

```bash
cd trabalho-pratico
python3 -m client.client
```

## Comandos do cliente

- `/register <username>`
- `/login <username>`
- `/add_contact <username>`
- `/list_contacts`
- `/online`
- `/send <username> <mensagem>`
- `/inbox`
- `/help`
- `/exit`

## Testes

```bash
python3 -m compileall trabalho-pratico
python3 trabalho-pratico/smoke_test.py
```

O smoke test valida:

- TLS
- register/login
- envio E2EE offline
- inbox
- ack

## Dados gerados localmente

O projeto gera dados locais em:

- `server/data/users.json`
- `server/data/messages.json`
- `server/data/server_cert.pem`
- `server/data/server_key.pem`
- `client/data/keys/`
- `client/data/sessions/`
- `client/data/tls/`

## Relatório

A descrição detalhada da arquitetura, modelo de segurança, primitivas criptográficas, garantias, valorizações e limitações encontra-se no relatório do projeto.
