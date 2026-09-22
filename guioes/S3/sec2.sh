#!/bin/bash

# Exercício 0

head -n 15 /etc/passwd
head -n 15 /etc/group

# Exercício 1

sudo adduser a104452 #pediu imensa coisa, por isso fiz da maneira que está abaixo
sudo adduser --disabled-password --gecos "" a104267
sudo adduser --disabled-password --gecos "" a104174

# Exercício 2

sudo groupadd -f grupo-ssi
sudo usermod -aG grupo-ssi a104174
sudo usermod -aG grupo-ssi a104267
sudo usermod -aG grupo-ssi a104452

sudo groupadd -f par-ssi
sudo usermod -aG par-ssi a104174
sudo usermod -aG par-ssi a104267

# Exercicio 3

tail -n 10 /etc/passwd
tail -n 10 /etc/group

    # em /etc/passwd aparecem entradas novas (os utilizadores criados).
    # em /etc/group aparecem os grupos novos e atualização dos membros (lista de utilizadores adicionados ao grupo).

# Exercício 4

sudo chown a104174 braga.txt

# Exercício 5

cat braga.txt

# Exercício 6

sudo passwd a104174
su - a104174

# Exercicio 7

id #uid=1003(a104174) gid=1003(a104174) groups=1003(a104174),100(users),1004(grupo-ssi),1005(par-ssi)
groups #a104174 users grupo-ssi par-ssi

# Exercicio 8

ls -l "/home/vboxuser/Desktop/Week 3" 
cat "/home/vboxuser/Desktop/Week 3/braga.txt"

    # o acesso falhou porque /home/vboxuser tinha permissões drwxr-x---, ou seja, “other” não tinha permissão de execução (x) dando 'permission denied' 

# Exercicio 9

cd "/home/vboxuser/Desktop/Week 3/dir2"
pwd
ls -ld .

# Para mudar para uma pasta é necessária permissão de execução (x) nessa pasta e em todas as pastas do caminho. Se faltar x em algum nível, o cd falha com “Permission denied”, mesmo que existam permissões de leitura (r).