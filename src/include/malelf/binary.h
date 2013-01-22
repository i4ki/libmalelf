#ifndef MALELF_BINARY_H
#define MALELF_BINARY_H

#include <stdlib.h>
#include <elf.h>

#include "types.h"
#include "ehdr.h"
#include "shdr.h"
#include "phdr.h"

typedef struct {
        MalelfEhdr ehdr;    /* ELF Header */
        MalelfPhdr phdr;    /* Elf Program Headers */
        MalelfShdr shdr;    /* Elf Section Headers */
} MalelfFormat;

typedef struct {
        char *fname;          /* Binary filename */
        _i32 fd;             /* Binary file descriptor */
        _u8* mem;            /* Binary content */
        _u32 size;           /* Binary size */
        MalelfFormat elf;    /* ELF Information */
        _u8 alloc_type;      /* System function used to allocate memory */
	_u32 class;
} MalelfBinary;


/*! Initialize MalelfBinary objetc. This method must be called.
 *
 *  \param bin a valid malelfbinary object.
 *
 */
extern void malelf_binary_init(MalelfBinary *bin);


/*!  Clean MalelfBinary objetc. This method must be called.
 *
 *  \param bin a valid malelfbinary object.
 *
 */
extern _i32 malelf_binary_close(MalelfBinary *bin);

/* SETTERS */


/*! Set the alloc type.
 *
 *  \param bin A valid MalelfBinary object.
 *  \alloc_type How the binary will be loaded. 
 *              (MALELF_ALLOC_MMAP or MALELF_ALLOC_MALLOC)
 */
extern void malelf_binary_set_alloc_type(MalelfBinary *bin, _u8 alloc_type);


/* GETTERS */


/*! Get the architecture class type from binary file.
 *
 *  \param bin A valid MalelfBinary object.
 *
 *  \return MALELF_ELF32 for arch 32 bits, MALELF_ELF32 for arch 64 bits or
 *          MALELF_ELFNONE for error.
 */
extern inline _i32 malelf_binary_get_class(MalelfBinary *bin);


/*! Get ELF Header.
 *
 *  \param bin A valid MalelfBinary object.
 *
 *  \return A valid MalelfEhdr.
 */
extern MalelfEhdr malelf_binary_get_ehdr(MalelfBinary *bin);


/*! Get Program Header Table.
 *
 *  \param bin A valid MalelfBinary object.
 *
 *  \return A valid MalelfPhdr.
 */
extern MalelfPhdr malelf_binary_get_phdr(MalelfBinary *bin);


/*! Get Section Header Table.
 *
 *  \param bin A valid MalelfBinary object.
 *
 *  \return A valid MalelfShdr.
 */
extern MalelfShdr malelf_binary_get_shdr(MalelfBinary *bin);


/*! Get alloc type.
 *
 *  \param bin A valid MalelfBinary object.
 *
 *  \return The alloc type (default: MALELF_ALLOC_MMAP).
 */
extern _u8 malelf_binary_get_alloc_type(MalelfBinary *bin);


/*! Load binary file.
 *
 *  \param bin A valid MalelfBinary object.
 *  \param fname Binary file name.
 *
 *  \return The malelf status.
 */
extern _i32 malelf_binary_open(char *fname, MalelfBinary *binary);


/*! Load binary file using mmap.
 *
 *  \param bin A valid MalelfBinary object.
 *  \param fname Binary file name.
 *
 *  \return The malelf status.
 */
extern _i32 malelf_binary_open_mmap(char *fname, MalelfBinary *binary);


/*! Load binary file using malloc.
 *
 *  \param bin A valid MalelfBinary object.
 *  \param fname Binary file name.
 *
 *  \return The malelf status.
 */
extern _i32 malelf_binary_open_malloc(char *fname, MalelfBinary *binary);


/*! Load Ehdr, Phdr and Shdr.
 *
 *  \param bin A valid MalelfBinary object.
 *
 *  \return The malelf status (MALELF_SUCCESS or MALELF_ERROR).
 */
extern _i32 malelf_binary_map(MalelfBinary *bin);


/*! Check ELf magic.
 *
 *  \param bin A valid MalelfBinary object.
 *
 *  \return The malelf status (MALELF_SUCCESS or MALELF_ENOT_ELF).
 */
extern inline _i32 malelf_binary_check_elf_magic(MalelfBinary *binary);


#endif /* MALELF_BINARY_H */
