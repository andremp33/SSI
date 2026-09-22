#!/bin/bash

# Exercicio 1

touch showfile.c

gcc showfile.c -o showfile
chmod 755 showfile

# Exercicio 2

sudo adduser userssi

# Exercicio 3

sudo chown userssi:userssi showfile braga.txt

# Exercicio 4

./showfile braga.txt

    # deu permission denied porque so permite que o dono execute, e o utilizador em que estamos agora não é o dono

# Exercicio 5

sudo chmod u+s showfile

# Exercicio 6

./showfile braga.txt
    # a resposta foi "Eu moro em Braga"
    # o processo tem permissões do userssi ao abrir o ficheiro braga.txt, conseguindo ler o seu conteúdo caso o userssi tenha permissão de leitura. Isto demonstra a diferença entre utilizador real (quem executa) e utilizador efetivo
