#ifndef MALELF_EHDR_H
#define MALELF_EHDR_H

#include <elf.h>

#include "defines.h"
#include "types.h"

MALELF_BEGIN_DECLS

/*!
 * \file ehdr.h
 * \brief A class used to control the ELF header.
 *
 * The MalelfEhdr union is an opaque data type. It
 * should only be accessed via the following functions. 
 *
 */
typedef union {
        Elf32_Ehdr *eh32;    /*!< 32-bits ELF Header */
        Elf64_Ehdr *eh64;    /*!< 64-bits ELF Header */
} MalelfEhdr;

typedef struct {
        _u16 name;
        _i32 value;
        char *meaning;
} MalelfEhdrType;

typedef struct {
        _u16 name;
        _i32 value;
        char *meaning;
} MalelfEhdrVersion;

typedef struct {
        _u16 name;
        _i32 value;
        char *meaning;
} MalelfEhdrMachine;

extern _i32 malelf_ehdr_get_type (MalelfEhdr *ehdr, 
                                  _u8 class, 
                                  MalelfEhdrType *me_type);

extern _i32 malelf_ehdr_get_machine(MalelfEhdr *ehdr, 
                                    _u8 class, 
                                    MalelfEhdrMachine *me_machine);

extern _i32 malelf_ehdr_get_version(MalelfEhdr *ehdr, 
                                    _u8 class, 
                                    MalelfEhdrVersion *version);

/*
extern _u8 malelf_ehdr_get_entry_point(MalelfEhdr *ehdr);
extern _u8 malelf_ehdr_get_phoff(MalelfEhdr *ehdr);
extern _u8 malelf_ehdr_get_shoff(MalelfEhdr *ehdr);
*/

extern _i32 malelf_ehdr_set(MalelfEhdr* ehdr, _u8 class, _u8 *mem, _u32 size);

extern _i32 malelf_ehdr_get_ehsize(MalelfEhdr *ehdr, _u8 class, _u32 *size);

extern _i32 malelf_ehdr_get_phentsize(MalelfEhdr *ehdr, 
                                      _u8 class, 
                                      _u32 *phentsize);

extern _i32 malelf_ehdr_get_phnum(MalelfEhdr *ehdr, _u8 class, _u32 *phnum);

extern _i32 malelf_ehdr_get_shentsize(MalelfEhdr *ehdr, 
                                      _u8 class, 
                                      _u32 *shentsize);

extern _i32 malelf_ehdr_get_shnum(MalelfEhdr *ehdr, _u8 class, _u32 *shnum);

extern _i32 malelf_ehdr_get_shstrndx(MalelfEhdr *ehdr, 
                                     _u8 class, 
                                     _u32 *shstrndx);

MALELF_END_DECLS


#endif /* MALELF_EHDR_H */
