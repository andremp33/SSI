#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    FILE *f;
    int c;

    if (argc != 2) {
        fprintf(stderr, "Uso: %s <ficheiro>\n", argv[0]);
        return 1;
    }

    f = fopen(argv[1], "r");
    if (!f) {
        perror("fopen");
        return 2;
    }

    while ((c = fgetc(f)) != EOF) putchar(c);

    fclose(f);
    return 0;
}