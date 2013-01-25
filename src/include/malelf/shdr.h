#ifndef MALELF_SHDR_H
#define MALELF_SHDR_H

#include <elf.h>

#include "types.h"

MALELF_BEGIN_DECLS

/*!
 * \file phdr.h
 * \brief A class used to control the section header table.
 *
 * The MalelfShdr union is an opaque data type. It
 * should only be accessed via the following functions. 
 *
 */
typedef union {
        Elf32_Shdr *h32;    /*!< 32-bits ELF Section Headers */
        Elf64_Shdr *h64;    /*!< 64-bits ELF Section Headers */
} MalelfShdr;





MALELF_END_DECLS


#endif /* MALELF_PHDR_H */
