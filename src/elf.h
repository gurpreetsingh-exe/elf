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

// This value marks the section header as inactive.
#define SHT_NULL          0x0

// This section holds information defined by the
// program, whose format and meaning are determined
// solely by the program.
#define SHT_PROGBITS      0x1

// This section holds a symbol table.
#define SHT_SYMTAB        0x2

// This section holds a string table.  An object file
// may have multiple string table sections.
#define SHT_STRTAB        0x3

// This section holds relocation entries with explicit addends.
#define SHT_RELA          0x4

// This section holds a symbol hash table.
#define SHT_HASH          0x5

// This section holds information for dynamic linking.
// An object file may have only one dynamic section.
#define SHT_DYNAMIC       0x6

// This section holds notes (Elf64_Nhdr).
#define SHT_NOTE          0x7

// A section of this type occupies no space in the
// file but otherwise resembles SHT_PROGBITS.
// Although this section contains no bytes, the
// sh_offset member contains the conceptual file
// offset.
#define SHT_NOBITS        0x8

// This section holds relocation offsets without explicit addends.
#define SHT_REL           0x9

// This section is reserved but has unspecified semantics.
#define SHT_SHLIB         0x0A

// This section holds a minimal set of dynamic linking symbols.
#define SHT_DYNSYM        0x0B

// This section contains an array of pointers to initialization functions.
#define SHT_INIT_ARRAY    0x0E

// This section contains an array of pointers to termination functions.
#define SHT_FINI_ARRAY    0x0F

// This section contains an array of pointers to functions
// that are invoked before all other initialization functions.
#define SHT_PREINIT_ARRAY 0x10

// This section defines a section group.
#define SHT_GROUP         0x11

// This section is associated with a section of type SHT_SYMTAB
// and is required if any of the section header indexes
// referenced by that symbol table contain the escape value SHN_XINDEX.
#define SHT_SYMTAB_SHNDX  0x12

// Values in this inclusive range are reserved for operating system-specific semantics.
#define SHT_LOOS          0x60000000
#define SHT_HIOS          0x6fffffff

// Values in this inclusive range are reserved for processor-specific semantics.
#define SHT_LOPROC        0x70000000
#define SHT_HIPROC        0x7fffffff

// This value specifies the lower bound of the range of indexes
// reserved for application programs.
#define SHT_LOUSER        0x80000000

// This value specifies the upper bound of the range of indexes
// reserved for application programs.
#define SHT_HIUSER        0xffffffff


typedef struct {
    uint32_t   sh_name;
    uint32_t   sh_type;
    uint64_t   sh_flags;
    uint64_t   sh_addr;
    uint64_t   sh_offset;
    uint64_t   sh_size;
    uint32_t   sh_link;
    uint32_t   sh_info;
    uint64_t   sh_addralign;
    uint64_t   sh_entsize;
} Elf64_Shdr;

const uint64_t shdr_size = sizeof(Elf64_Shdr);
