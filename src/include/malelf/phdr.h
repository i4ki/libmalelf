#ifndef MALELF_PHDR_H
#define MALELF_PHDR_H

#include <elf.h>

#include "types.h"

MALELF_BEGIN_DECLS

/*!
 * \file phdr.h
 * \brief A class used to control the program headers.
 *
 * The MalelfPhdr union is an opaque data type. It
 * should only be accessed via the following functions. 
 *
 */
typedef union {
        Elf32_Phdr *ph32;    /*!< 32-bits ELF Program Headers */
        Elf64_Phdr *ph64;    /*!< 64-bits ELF Program Headers */
} MalelfPhdr;




MALELF_END_DECLS


#endif /* MALELF_PHDR_H */
