#!/bin/bash

# Exercicio 1

getfacl porto.txt

# Exercicio 2

sudo setfacl -m g:grupo-ssi:w porto.txt

# Exercicio 3

getfacl porto.txt

    # Antes
    # file: porto.txt
    # owner: vboxuser
    # group: vboxuser
    # user::r-x
    # group::---
    # other::---

    # Depois
    # file: porto.txt
    # owner: vboxuser
    # group: vboxuser
    # user::r-x
    # group::---
    # group:grupo-ssi:-w-
    # mask::-w-
    # other::---

    # ou seja, depois do setfacl, passa a existir uma entrada extra do tipo group:grupo-ssi:... e aparece também uma linha mask:. A mask limita as permissões efetivas para utilizadores/grupos definidos por ACL.

# Exercicio 4

su - a104174

echo "Adoro o porto" >> porto.txt
cat porto.txt

    # Se o utilizador pertencer ao grupo-ssi, a escrita funciona devido à ACL (group:grupo-ssi:w ou rw). A leitura só funciona se o utilizador tiver permissão de leitura (por permissões tradicionais ou por ACL rw).