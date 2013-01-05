#ifndef MALELF_BINARY_H
#define MALELF_BINARY_H

#include <stdlib.h>
#include <elf.h>

#include "types.h"

/* ELF Architecture Type */
#define MALELF_ELF32 ELFCLASS32
#define MALELF_ELF64 ELFCLASS64
#define MALELF_ELFNONE ELFCLASSNONE

/* System-function used to allocate buffer */
#define MALELF_ALLOC_MMAP 0
#define MALELF_ALLOC_MALLOC 1

typedef union {
        Elf32_Ehdr *eh32;    /* 32-bits ELF Header */
        Elf64_Ehdr *eh64;    /* 64-bits ELF Header */
} malelfEhdr;

typedef union {
        Elf32_Phdr *ph32;    /* 32-bits ELF Program Headers */
        Elf64_Phdr *ph64;    /* 64-bits ELF Program Headers */
} malelfPhdr;

typedef union {
        Elf32_Shdr *sh32;    /* 32-bits ELF Section Headers */
        Elf64_Shdr *sh64;    /* 64-bits ELF Section Headers */
} malelfShdr;

typedef struct {
        malelfEhdr *ehdr;    /* ELF Header */
        malelfPhdr *phdr;    /* Elf Program Headers */
        malelfShdr *shdr;    /* Elf Section Headers */
} malelfFormat;

typedef struct {
        _u8 *fname;          /* Binary filename */
        _i32 fd;             /* Binary file descriptor */
        _u8* mem;            /* Binary content */
        _u32 size;           /* Binary size */
        malelfFormat elf;    /* ELF Information */
        _u8 alloc_type;      /* System function used to allocate memory */
} malelfBinary;

extern inline _i32 malelf_elf_arch(malelfBinary *bin);
extern _i32 malelf_ehdr_set(malelfEhdr *ehdr, malelfBinary *bin);
extern _i32 _malelf_internal_map(malelfBinary *bin);
extern inline _i32 malelf_check_elf_magic(malelfBinary *binary);
extern _i32 malelf_open_generic(const char *fname,
                                 malelfBinary *binary,
                                 _u8 alloc_type);
extern _i32 malelf_open(const char *fname, malelfBinary *binary);
extern _i32 malelf_open_malloc(const char *fname, malelfBinary *binary);
extern _i32 _malelf_internal_map(malelfBinary *bin);
#endif
