#!/bin/bash

# Exercício 1

touch lisboa.txt
touch porto.txt
touch braga.txt

echo "Lisboa é a capital de Portugal" > lisboa.txt
echo "Porto é a cidade mais bonita de Portugal" > porto.txt
echo "Eu moro em Braga" > braga.txt

# Exercício 2

ls -l lisboa.txt

# Exercicio 3

chmod a=rw lisboa.txt

# Exercicio 4

chmod 500 porto.txt

# Exercicio 5

chmod 400 braga.txt

# Exercicio 6

mkdir dir1 dir2
ls -ld dir1 dir2

# Exercicio 7

chmod go-x dir2