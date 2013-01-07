#ifndef MALELF_EHDR_H
#define MALELF_EHDR_H

#include <elf.h>

#include <malelf/defines.h>
#include <malelf/types.h>

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





MALELF_END_DECLS


#endif /* MALELF_EHDR_H */
