#!/bin/bash

# Exercicio 1

capsh --print

# Exercicio 2

touch webserver.c

gcc -o webserver webserver.c
chmod 755 webserver

./webserver 4050

# Exercicio 3

./webserver 80

    # bind: Permission denied
    # Em Linux, portas < 1024 são “privileged ports”. Um utilizador normal não consegue fazer bind() a essas portas sem privilégios adicionais (root) ou sem a capability apropriada.

sudo setcap 'cap_net_bind_service=+ep' ./webserver
getcap ./webserver
./webserver 80

    # O executável passa a ter CAP_NET_BIND_SERVICE nos conjuntos Effective/Permitted, permitindo fazer bind à porta 80 sem ser root. Isto é mais seguro do que setuid root, porque dá apenas o privilégio mínimo necessário.