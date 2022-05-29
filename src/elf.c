#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>

#define EI_MAG 4

uint8_t e_ident[EI_MAG] = {0x7f, 0x45, 0x4c, 0x46};

void read_elf(const char* filename, uint8_t* buf) {
    for (size_t i = 0; i < EI_MAG; ++i) {
        if (buf[i] != e_ident[i]) {
            fprintf(stderr, "ERROR: `%s` is not a valid elf file\n", filename);
            exit(1);
        }
    }
    printf("INFO: `%s` is a valid elf file\n", filename);
}

int main(int argc, char** argv) {
    (void)argc;

    if (argv[1] == NULL) {
        fprintf(stderr, "USAGE: ./elf [filename]\n");
        exit(1);
    }

    char* filename = argv[1];
    FILE* f = fopen(filename, "rb");
    if (f == NULL) {
        fprintf(stderr, "ERROR: Cannot open `%s`\n    %s\n", filename, strerror(errno));
        exit(1);
    }

    struct stat statbuf;
    int res = fstat(fileno(f), &statbuf);
    if (res == -1) {
        fprintf(stderr, "ERROR: when collecting info about `%s`\n    %s\n", filename, strerror(errno));
        exit(1);
    }

    size_t filesz = statbuf.st_size;
    // I guess allocating 
    uint8_t* buffer = (uint8_t*)malloc(filesz);
    size_t sz = fread(buffer, sizeof(uint8_t), filesz, f);
    if (sz != filesz) {
        fprintf(stderr,
            "ERROR: read size (%ld) is different than actual size (%ld)\n    %s\n",
            sz, filesz,
            strerror(errno));
        exit(1);
    }
    read_elf(filename, buffer);
    free(buffer);

    return 0;
}
