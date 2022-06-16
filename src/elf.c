#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>

#include "elf.h"

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

static inline uint64_t read_u64(const uint8_t* buf, uint64_t addr) {
    return (buf[addr])
        | buf[addr + 1] << 8
        | buf[addr + 2] << 16
        | buf[addr + 3] << 24
        | (uint64_t)buf[addr + 4] << 32
        | (uint64_t)buf[addr + 5] << 40
        | (uint64_t)buf[addr + 6] << 48
        | (uint64_t)buf[addr + 7] << 56;
}

static inline uint32_t read_u32(const uint8_t* buf, uint32_t addr) {
    return (buf[addr])
        | buf[addr + 1] << 8
        | buf[addr + 2] << 16
        | buf[addr + 3] << 24;
}

static inline uint16_t read_u16(const uint8_t* buf, uint16_t addr) {
    return buf[addr] | buf[addr + 1] << 8;
}

void dump_header(Elf64_Ehdr* ehdr) {
    printf("ELF Header:\n  Magic:   ");
    for (size_t i = 0; i < 16; ++i) {
        printf("%02x ", ehdr->e_ident[i]);
    }

    printf("\n");
    printf("  Class: \t\t\t%s\n", elf_class[ehdr->e_ident[4] - 1]);
    printf("  Data: \t\t\t%s endian\n", elf_data[ehdr->e_ident[5] - 1]);
    printf("  Version: \t\t\t%d\n", ehdr->e_ident[6]);
    printf("  OS/ABI: \t\t\t%s\n", elf_abi[ehdr->e_ident[7]]);
    printf("  ABI Version: \t\t\t%d\n", ehdr->e_ident[0x08]);
    printf("  Type: \t\t\t%s\n", elf_type[ehdr->e_type]);
    printf("  Machine: \t\t\tAdvanced Micro Devices X86-64\n");
    printf("  Version: \t\t\t%d\n", ehdr->e_version);
    printf("  Entry Point: \t\t\t0x%lx\n", ehdr->e_entry);
    printf("  Program Header Start: \t%ld (bytes into file)\n", ehdr->e_phoff);
    printf("  Section Header Start: \t%ld (bytes into file)\n", ehdr->e_shoff);
    printf("  Flags: \t\t\t0x%x\n", ehdr->e_flags);
    printf("  Size of this header: \t\t%d (bytes)\n", ehdr->e_ehsize);
    printf("  Size of Program headers: \t%d (bytes)\n", ehdr->e_phentsize);
    printf("  Number of Program headers: \t%d\n", ehdr->e_phnum);
    printf("  Size of Section headers: \t%d (bytes)\n", ehdr->e_shentsize);
    printf("  Number of Section headers: \t%d\n", ehdr->e_shnum);
    printf("  String table index: \t\t%d\n", ehdr->e_shstrndx);
}

const char* phdr_type(uint32_t type) {
    switch (type) {
        case PT_NULL:
            return "NULL";
        case PT_LOAD:
            return "LOAD";
        case PT_DYNAMIC:
            return "DYNAMIC";
        case PT_INTERP:
            return "INTERP";
        case PT_NOTE:
            return "NOTE";
        case PT_SHLIB:
            return "SHLIB";
        case PT_PHDR:
            return "PHDR";
        default:
            return "UNDEFINED";
    }
}

void dump_program_headers(Elf64_Ehdr* ehdr, Elf64_Phdr** phdr_list) {
    printf("File type: %s\n", elf_type[ehdr->e_type]);
    printf("Entry point: %#lx\n", ehdr->e_entry);
    printf("There are %d program header, starting at offset %ld\n", ehdr->e_phnum, ehdr->e_phoff);
    printf("\nProgram Headers:\n");
    printf("  Type\
                       Offset\
             FileSiz\
            VirtAddr\
              MemSiz\
            PhysAddr\
     Flags\
     Align\n");
    for (size_t i = 0; i < ehdr->e_phnum; ++i) {
        printf("  %-13s", phdr_type(phdr_list[i]->p_type));
        printf("  %#18lx", phdr_list[i]->p_offset);
        printf("  %#18lx", phdr_list[i]->p_filesz);
        printf("  %#18lx", phdr_list[i]->p_vaddr);
        printf("  %#18lx", phdr_list[i]->p_memsz);
        printf("  %#18lx", phdr_list[i]->p_paddr);
        printf("  %8x", phdr_list[i]->p_flags);
        printf("  %#8lx", phdr_list[i]->p_align);
        printf("\n");
    }
}

const char* shdr_type(uint32_t type) {
    switch (type) {
        case SHT_NULL:
            return "NULL";
        case SHT_PROGBITS:
            return "PROGBITS";
        case SHT_SYMTAB:
            return "SYMTAB";
        case SHT_STRTAB:
            return "STRTAB";
        case SHT_RELA:
            return "RELA";
        case SHT_HASH:
            return "HASH";
        case SHT_DYNAMIC:
            return "DYNAMIC";
        case SHT_NOTE:
            return "NOTE";
        case SHT_NOBITS:
            return "NOBITS";
        case SHT_REL:
            return "REL";
        case SHT_SHLIB:
            return "SHLIB";
        case SHT_DYNSYM:
            return "DYNSYM";
        case SHT_INIT_ARRAY:
            return "INIT_ARRAY";
        case SHT_FINI_ARRAY:
            return "FINI_ARRAY";
        case SHT_PREINIT_ARRAY:
            return "PREINIT_ARRAY";
        case SHT_GROUP:
            return "GROUP";
        case SHT_SYMTAB_SHNDX:
            return "SYMTAB_SHNDX";
        case SHT_LOOS:
            return "LOOS";
        case SHT_HIOS:
            return "HIOS";
        case SHT_LOPROC:
            return "LOPROC";
        case SHT_HIPROC:
            return "HIPROC";
        case SHT_LOUSER:
            return "LOUSER";
        case SHT_HIUSER:
            return "HIUSER";
        default:
            return "UNDEFINED";
    }
}

void dump_section_headers(Elf64_Ehdr* ehdr, Elf64_Shdr** shdr_list, uint8_t* strtab) {
    printf("There are %d section headers, starting at offset %#lx\n", ehdr->e_shnum, ehdr->e_shoff);
    printf("\nSection Headers:\n");
    printf("  Name\
                         Type\
           Address\
            Offset\
              Size\
           EntSize\
    Flags\
  Link\
  Info\
  Align\n");

    for (size_t i = 0; i < ehdr->e_shnum; ++i) {
        char buffer[128] = {0};
        for (size_t j = 0; strtab[j + shdr_list[i]->sh_name]; ++j) {
            buffer[j] = strtab[j + shdr_list[i]->sh_name];
        }
        printf("  %-21s", buffer);
        printf("  %10s", shdr_type(shdr_list[i]->sh_type));
        printf("  %#16lx", shdr_list[i]->sh_addr);
        printf("  %#16lx", shdr_list[i]->sh_offset);
        printf("  %#16lx", shdr_list[i]->sh_size);
        printf("  %#16lx", shdr_list[i]->sh_entsize);
        printf("  %7ld", shdr_list[i]->sh_flags);
        printf("  %4d", shdr_list[i]->sh_link);
        printf("  %4d", shdr_list[i]->sh_info);
        printf("  %5ld", shdr_list[i]->sh_addralign);
        printf("\n");
    }
}

void read_elf_header(const char* filename, uint8_t* buf, Elf64_Ehdr* ehdr) {
    for (size_t i = 0; i < EI_MAG; ++i) {
        if (buf[i] != e_ident[i]) {
            fprintf(stderr, "ERROR: `%s` is not a valid elf file\n", filename);
            exit(1);
        }
    }

    for (size_t i = 0; i < 16; ++i) {
        ehdr->e_ident[i] = buf[i];
    }

    ehdr->e_type      = read_u16(buf, 0x10);
    ehdr->e_machine   = read_u16(buf, 0x12);
    ehdr->e_version   = read_u32(buf, 0x14);
    ehdr->e_entry     = read_u64(buf, 0x18);
    ehdr->e_phoff     = read_u64(buf, 0x20);
    ehdr->e_shoff     = read_u64(buf, 0x28);
    ehdr->e_flags     = read_u32(buf, 0x30);
    ehdr->e_ehsize    = read_u16(buf, 0x34);
    ehdr->e_phentsize = read_u16(buf, 0x36);
    ehdr->e_phnum     = read_u16(buf, 0x38);
    ehdr->e_shentsize = read_u16(buf, 0x3a);
    ehdr->e_shnum     = read_u16(buf, 0x3c);
    ehdr->e_shstrndx  = read_u16(buf, 0x3e);
}

Elf64_Phdr* read_program_header(uint8_t* buf, uint64_t phoff) {
    Elf64_Phdr* phdr = (Elf64_Phdr*)malloc(phdr_size);

    phdr->p_type   = read_u32(buf, 0x00 + phoff);
    phdr->p_flags  = read_u32(buf, 0x04 + phoff);
    phdr->p_offset = read_u64(buf, 0x08 + phoff);
    phdr->p_vaddr  = read_u64(buf, 0x10 + phoff);
    phdr->p_paddr  = read_u64(buf, 0x18 + phoff);
    phdr->p_filesz = read_u64(buf, 0x20 + phoff);
    phdr->p_memsz  = read_u64(buf, 0x28 + phoff);
    phdr->p_align  = read_u64(buf, 0x30 + phoff);

    return phdr;
}

void read_program_headers(uint8_t* buf, Elf64_Ehdr* ehdr, Elf64_Phdr** phdr_list) {
    uint64_t phoff = ehdr->e_phoff;
    for (size_t i = 0; i < ehdr->e_phnum; ++i) {
        phdr_list[i] = read_program_header(buf, phoff);
        phoff += phdr_size;
    }
}

Elf64_Shdr* read_section_header(uint8_t* buf, uint64_t shoff) {
    Elf64_Shdr* shdr = (Elf64_Shdr*)malloc(shdr_size);

    shdr->sh_name      = read_u32(buf, 0x00 + shoff);
    shdr->sh_type      = read_u32(buf, 0x04 + shoff);
    shdr->sh_flags     = read_u64(buf, 0x08 + shoff);
    shdr->sh_addr      = read_u64(buf, 0x10 + shoff);
    shdr->sh_offset    = read_u64(buf, 0x18 + shoff);
    shdr->sh_size      = read_u64(buf, 0x20 + shoff);
    shdr->sh_link      = read_u32(buf, 0x28 + shoff);
    shdr->sh_info      = read_u32(buf, 0x2c + shoff);
    shdr->sh_addralign = read_u64(buf, 0x30 + shoff);
    shdr->sh_entsize   = read_u64(buf, 0x38 + shoff);

    return shdr;
}

void read_section_headers(uint8_t* buf, Elf64_Ehdr* ehdr, Elf64_Shdr** shdr_list) {
    uint64_t shoff = ehdr->e_shoff;
    for (size_t i = 0; i < ehdr->e_shnum; ++i) {
        shdr_list[i] = read_section_header(buf, shoff);
        shoff += shdr_size;
    }
}

void read_elf(const char* filename, uint8_t* buf) {
    Elf64_Ehdr* ehdr = (Elf64_Ehdr*)malloc(ehdr_size);
    read_elf_header(filename, buf, ehdr);

    Elf64_Phdr** phdr_list = (Elf64_Phdr**)malloc(phdr_size * ehdr->e_phnum);
    read_program_headers(buf, ehdr, phdr_list);

    Elf64_Shdr** shdr_list = (Elf64_Shdr**)malloc(shdr_size * ehdr->e_shnum);
    read_section_headers(buf, ehdr, shdr_list);

    Elf64_Shdr* string_table = shdr_list[ehdr->e_shstrndx];
    uint8_t* strtab = (uint8_t*)malloc(string_table->sh_size);
    memcpy(strtab, buf + string_table->sh_offset, string_table->sh_size);

    free(strtab);
    for (size_t i = 0; i < ehdr->e_shnum; ++i) {
        free(shdr_list[i]);
    }
    free(shdr_list);

    for (size_t i = 0; i < ehdr->e_phnum; ++i) {
        free(phdr_list[i]);
    }
    free(phdr_list);
    free(ehdr);
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
