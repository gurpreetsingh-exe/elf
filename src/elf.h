#include <stdint.h>

#define EI_NIDENT 16

typedef struct {
    unsigned char e_ident[EI_NIDENT];
    uint16_t      e_type;
    uint16_t      e_machine;
    uint32_t      e_version;
    uint64_t      e_entry;
    uint64_t      e_phoff;
    uint64_t      e_shoff;
    uint32_t      e_flags;
    uint16_t      e_ehsize;
    uint16_t      e_phentsize;
    uint16_t      e_phnum;
    uint16_t      e_shentsize;
    uint16_t      e_shnum;
    uint16_t      e_shstrndx;
} Elf64_Ehdr;

const uint64_t ehdr_size = sizeof(Elf64_Ehdr);


// Program header types

// The array element is unused and the other
// members' values are undefined
#define PT_NULL     0x00000000

// Specifies a loadable segment,
// described by p_filesz and p_memsz.
#define PT_LOAD     0x00000001

// Specifies dynamic linking information.
#define PT_DYNAMIC  0x00000002

// Specifies the location and size of a null-terminated
// pathname to invoke as an interpreter.
#define PT_INTERP   0x00000003

// Specifies the location of notes (Elf64_Nhdr)
#define PT_NOTE     0x00000004

// This segment type is reserved but has unspecified semantics.
#define PT_SHLIB    0x00000005

// The array element, if present, specifies the
// location and size of the program header table
// itself, both in the file and in the memory image
// of the program.
#define PT_PHDR     0x00000006

// Values in the inclusive range [PT_LOPROC,
// PT_HIPROC] are reserved for processor-specific
// semantics.
#define PT_LOPROC   0x70000000
#define PT_HIPROC   0x7FFFFFFF


typedef struct {
    uint32_t   p_type;
    uint32_t   p_flags;
    uint64_t   p_offset;
    uint64_t   p_vaddr;
    uint64_t   p_paddr;
    uint64_t   p_filesz;
    uint64_t   p_memsz;
    uint64_t   p_align;
} Elf64_Phdr;

const uint64_t phdr_size = sizeof(Elf64_Phdr);
