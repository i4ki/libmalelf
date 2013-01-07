#ifndef MALELF_BINARY_H
#define MALELF_BINARY_H

#include <stdlib.h>
#include <elf.h>

#include "types.h"
#include "ehdr.h"
#include "shdr.h"
#include "phdr.h"

typedef struct {
        MalelfEhdr *ehdr;    /* ELF Header */
        MalelfPhdr *phdr;    /* Elf Program Headers */
        MalelfShdr *shdr;    /* Elf Section Headers */
} MalelfFormat;

typedef struct {
        _u8 *fname;          /* Binary filename */
        _i32 fd;             /* Binary file descriptor */
        _u8* mem;            /* Binary content */
        _u32 size;           /* Binary size */
        MalelfFormat elf;    /* ELF Information */
        _u8 alloc_type;      /* System function used to allocate memory */
	_u32 class;
} MalelfBinary;


/* SETTERS */


/*! Stores the address ELF Header from binary file.
 *
 *  \param ehdr MalelfEhdr object will store the ELF Header address.
 *  \param bin A valid MalelfBinary object.
 *
 *  \return MALELF_SUCCESS if ehdr was successful set, 
 *          otherwise returns MALELF_ERROR.
 */
extern _i32 malelf_binary_set_ehdr(MalelfEhdr *ehdr, MalelfBinary *bin);


/*! Stores the address Program Header Table from binary file.
 *
 *  \param phdr MalelfPhdr object will store the Program Header Table address.
 *  \param bin A valid MalelfBinary object.
 *
 *  \return MALELF_SUCCESS if phdr was successful set, 
 *          otherwise returns MALELF_ERROR.
 */
extern _i32 malelf_binary_set_phdr(MalelfPhdr *phdr, MalelfBinary *bin);


/*! Stores the address Section Header Table from binary file.
 *
 *  \param ehdr MalelfShdr object will store the Section Header Table address.
 *  \param bin A valid MalelfBinary object.
 *
 *  \return MALELF_SUCCESS if shdr was successful set, 
 *          otherwise returns MALELF_ERROR.
 */
extern _i32 malelf_binary_set_shdr(MalelfPhdr *phdr, MalelfBinary *bin);


/* GETTERS */


/*! Get the arch type from binary file.
 *
 *  \param bin A valid MalelfBinary object.
 *
 *  \return MALELF_ELF32 for arch 32 bits, MALELF_ELF32 for arch 64 bits or
 *          MALELF_ELFNONE for error.
 */
extern inline _i32 malelf_binary_get_arch(MalelfBinary *bin);


/*! Get ELF Header.
 *
 *  \param bin A valid MalelfBinary object.
 *
 *  \return A valid pointer to a MalelfEhdr, or NULL if some error ocurred.
 */
extern MalelfEhdr *malelf_binary_get_ehdr(MalelfBinary *bin);


/*! Get Program Header Table.
 *
 *  \param bin A valid MalelfBinary object.
 *
 *  \return A valid pointer to a MalelfPhdr, or NULL if some error ocurred.
 */
extern MalelfPhdr *malelf_binary_get_phdr(MalelfBinary *bin);


/*! Get Section Header Table.
 *
 *  \param bin A valid MalelfBinary object.
 *
 *  \return A valid pointer to a MalelfShdr, or NULL if some error ocurred.
 */
extern MalelfShdr *malelf_binary_get_shdr(MalelfBinary *bin);


extern _i32 malelf_binary_map(MalelfBinary *bin);


extern inline _i32 malelf_binary_check_elf_magic(MalelfBinary *binary);


extern _i32 malelf_binary_open_generic(const char *fname,
                                       MalelfBinary *binary,
                                       _u8 alloc_type);


extern _i32 malelf_binary_open(const char *fname, MalelfBinary *binary);


extern _i32 malelf_binary_open_malloc(const char *fname, MalelfBinary *binary);


#endif
