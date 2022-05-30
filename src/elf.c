#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>

#define EI_MAG 4
#define EI_PAD 7

uint8_t e_ident[EI_MAG] = {0x7f, 0x45, 0x4c, 0x46};
const char* elf_class[] = {"32-bit", "64-bit"};
const char* elf_data[] = {"little", "big"};

// Maybe just remove this and hardcode `System V` :kekw:
const char* elf_abi[] = {
    "System V",
    "HP-UX",
    "NetBSD",
    "Linux",
    "GNU Hurd",
    "Solaris",
    "AIX (Monterey)",
    "IRIX",
    "FreeBSD",
    "Tru64",
    "Novell Modesto",
    "OpenBSD",
    "OpenVMS",
    "NonStop Kernel",
    "AROS",
    "FenixOS",
    "Nuxi CloudABI",
    "Stratus Technologies OpenVOS",
};
const char* elf_type[] = {
    "None",
    "Relocatable",
    "Executable",
    "Shader Object",
    "Core file",
};

uint64_t read_u64(const uint8_t* buf, uint64_t addr) {
    return (buf[addr])
        | buf[addr + 1] << 8
        | buf[addr + 2] << 16
        | buf[addr + 3] << 24
        | (uint64_t)buf[addr + 4] << 32
        | (uint64_t)buf[addr + 5] << 40
        | (uint64_t)buf[addr + 6] << 48
        | (uint64_t)buf[addr + 7] << 56;
}

uint32_t read_u32(const uint8_t* buf, uint32_t addr) {
    return (buf[addr])
        | buf[addr + 1] << 8
        | buf[addr + 2] << 16
        | buf[addr + 3] << 24;
}

void read_elf_header(const char* filename, uint8_t* buf) {
    for (size_t i = 0; i < EI_MAG; ++i) {
        if (buf[i] != e_ident[i]) {
            fprintf(stderr, "ERROR: `%s` is not a valid elf file\n", filename);
            exit(1);
        }
    }

    printf("Class: \t\t\t\t%s\n\
Data: \t\t\t\t%s endian\n\
Version: \t\t\t%d\n\
OS/ABI: \t\t\t%s\n\
ABI Version: \t\t\t%d\n\
Type: \t\t\t\t%s\n\
Machine: \t\t\tAdvanced Micro Devices X86-64\n\
Version: \t\t\t%d\n\
Entry Point: \t\t\t0x%lx\n\
Program Header Start: \t\t%ld (bytes into file)\n\
Section Header Start: \t\t%ld (bytes into file)\n\
Flags: \t\t\t\t0x%x\n\
Size of this header: \t\t%d (bytes)\n\
Size of Program headers: \t%d (bytes)\n\
Number of Program headers: \t%d\n\
Size of Section headers: \t%d (bytes)\n\
Number of Section headers: \t%d\n\
String table index: \t\t%d\n",
        elf_class[buf[4] - 1],
        elf_data[buf[5] - 1],
        buf[6],
        elf_abi[buf[7]],
        buf[8],
        elf_type[buf[9 + EI_PAD]],
        buf[0x14],
        read_u64(buf, 0x18),
        read_u64(buf, 0x20),
        read_u64(buf, 0x28),
        read_u32(buf, 0x30),
        buf[0x34] | buf[0x34 + 1] << 8,
        buf[0x36] | buf[0x36 + 1] << 8,
        buf[0x38] | buf[0x38 + 1] << 8,
        buf[0x3a] | buf[0x3a + 1] << 8,
        buf[0x3c] | buf[0x3c + 1] << 8,
        buf[0x3e] | buf[0x3e + 1] << 8);
}

void read_elf(const char* filename, uint8_t* buf) {
    read_elf_header(filename, buf);
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
    uint8_t* buffer = (uint8_t*)malloc(filesz);
    size_t sz = fread(buffer, sizeof(uint8_t), filesz, f);
    if (sz != filesz) {
        fprintf(stderr,
            "ERROR: read size (%ld) is different than actual size (%ld)\n    %s\n",
            sz, filesz,
            strerror(errno));
        exit(1);
    }
    fclose(f);

    read_elf(filename, buffer);
    free(buffer);

    return 0;
}
