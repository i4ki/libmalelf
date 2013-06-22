/*
 * The libmalelf is an evil library that could be used for good! It was
 * developed with the intent to assist in the process of infecting
 * binaries and provide a safe way to analyze malwares.
 *
 * Evil using this library is the responsibility of the programmer.
 *
 * Author:
 *         Tiago Natel de Moura <natel@secplus.com.br>
 *
 * Contributorss:
 *         Daniel Ricardo dos Santos <danielricardo.santos@gmail.com>
 *         Paulo Leonardo Benatto    <benatto@gmail.com>
 *
 * Copyright 2012, 2013 by Tiago Natel de Moura. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef MALELF_BINARY_H
#define MALELF_BINARY_H

#include <stdlib.h>
#include <elf.h>

#include "types.h"
#include "ehdr.h"
#include "shdr.h"
#include "phdr.h"

typedef struct {
        char *fname;         /* Binary filename */
        char *bkpfile;       /* Filename of backup'ed file in case of
                                write operations */
        _i32 fd;             /* Binary file descriptor */
        _u8 *mem;            /* Binary content */
        _u32 size;           /* Binary size */
        MalelfEhdr ehdr;     /* ELF Header */
        MalelfPhdr phdr;     /* Elf Program Headers */
        MalelfShdr shdr;     /* Elf Section Headers */
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
 *  \param class Architeture class of binary saved.
 *
 *  \return MALELF_SUCCESS if class was successful saved, otherwise
 *          MALELF_ERROR.
 */
extern _u32 malelf_binary_get_class(MalelfBinary *bin, _u8 *class);


/*! Get ELF Header.
 *
 *  \param bin A valid MalelfBinary object.
 *  \param ehdr Saved ELF Header of the binary.
 *
 *  \return MALELF_SUCCESS if MalelfEhdr was successful saved.
 */
extern _u32 malelf_binary_get_ehdr(MalelfBinary *bin, MalelfEhdr *ehdr);


/*! Get Program Header Table.
 *
 *  \param bin A valid MalelfBinary object.
 *  \param phdr Saved Program Header of the binary.
 *
 *  \return MALELF_SUCCESS if MalelfPhdr was successful saved.
 */
extern _u32 malelf_binary_get_phdr(MalelfBinary *bin, MalelfPhdr *phdr);


/*! Get Section Header Table.
 *
 *  \param bin A valid MalelfBinary object.
 *  \param shdr Saved Section Header of the binary.
 *
 *  \return MALELF_SUCCESS if MalelfShdr was successful saved.
 */
extern _u32 malelf_binary_get_shdr(MalelfBinary *bin, MalelfShdr *shdr);


/*! Get alloc type.
 *
 *  \param bin A valid MalelfBinary object.
 *  \param alloc_type Saved alloc_type.
 *
 *  \return MALELF_SUCCESS if alloc_type was successful saved.
 */
extern _u32 malelf_binary_get_alloc_type(MalelfBinary *bin, _u8 *alloc_type);


/*! Load binary file.
 *
 *  \param bin A valid MalelfBinary object.
 *  \param fname Binary file name.
 *
 *  \return The malelf status.
 */
extern _i32 malelf_binary_open(MalelfBinary *binary, char *fname);

extern _i32 malelf_binary_openw(MalelfBinary *binary, char *fname);


/*! Load binary file using mmap.
 *
 *  \param bin A valid MalelfBinary object.
 *  \param fname Binary file name.
 *
 *  \return The malelf status.
 */
extern _i32 malelf_binary_open_mmap(MalelfBinary *binary, char *fname);

extern _u32 malelf_binary_mmap_from(MalelfBinary *dest,
                                    MalelfBinary *src);

extern _u32 malelf_binary_malloc_from(MalelfBinary *dest,
                                      MalelfBinary *src);

extern _u32 malelf_binary_add_byte(MalelfBinary *bin,
                                          void *byte);

extern _u32 malelf_binary_copy_data(MalelfBinary *dest,
                                    MalelfBinary *src,
                                    _u32 offset_start,
                                    _u32 offset_end);


/*! Load binary file using malloc.
 *
 *  \param bin A valid MalelfBinary object.
 *  \param fname Binary file name.
 *
 *  \return The malelf status.
 */
extern _i32 malelf_binary_open_malloc(MalelfBinary *binary, char *fname);


/*! Load Ehdr, Phdr and Shdr.
 *
 *  \param bin A valid MalelfBinary object.
 *
 *  \return The malelf status (MALELF_SUCCESS or MALELF_ERROR).
 */
extern _u32 malelf_binary_map(MalelfBinary *bin);


/*! Check ELf magic.
 *
 *  \param bin A valid MalelfBinary object.
 *
 *  \return The malelf status (MALELF_SUCCESS or MALELF_ENOT_ELF).
 */
extern _u32 malelf_binary_check_elf_magic(MalelfBinary *binary);


/*! Get segment.
 *
 *  \param bin A valid MalelfBinary object.
 *  \param idx The index of segment.
 *  \param segment The segment saved.
 *
 *  \return MALELF_SUCCESS if the operation succeeded.
 */
extern _u32 malelf_binary_get_segment(MalelfBinary *bin,
                                      _u32 idx,
                                      MalelfSegment *segment);


/*! Get section name.
 *
 *  \param bin A valid MalelfBinary object.
 *  \param idx The index of section.
 *  \param name The section name saved.
 *
 *  \return MALELF_SUCCESS if the operation succeeded, otherwise MALELF_ERROR.
 */
extern _u32 malelf_binary_get_section_name(MalelfBinary *bin,
                                           _u32 idx,
                                           char **name);


/*! Get section.
 *
 *  \param bin A valid MalelfBinary object.
 *  \param idx The index of section.
 *  \param section The section information saved.
 *
 *  \return MALELF_SUCCESS if the operation succeeded, otherwise MALELF_ERROR.
 */
extern _u32 malelf_binary_get_section(MalelfBinary *bin,
                                      _u32 idx,
                                      MalelfSection *section);


/*! Write a MalelfBinary file on disk.
 *
 *  \param bin A valid MalelfBinary object.
 *  \param fname The file name to write the binary.
 *
 *  \return MALELF_SUCCESS if the operation succeeded, otherwise MALELF_ERROR.
 */
extern _u32 malelf_binary_write_elf(MalelfBinary *bin, const char *fname) __attribute__((deprecated));

/*! Write a MalelfBinary file on disk.
 *
 *  \param bin A valid MalelfBinary object.
 *  \param fname The file name to write the binary.
 *
 *  \return MALELF_SUCCESS if the operation succeeded,
 * otherwise MALELF_ERROR.
 */
extern _u32 malelf_binary_write(MalelfBinary *bin,
                                char *fname,
                                _u8 overwrite);

extern _u32 malelf_binary_create(MalelfBinary *output, _u8 overwrite);

/*! Crate executable file arch 32.
 *
 *  \param bin A valid MalelfBinary object.
 *
 *  \return MALELF_SUCCESS if the operation succeeded, otherwise MALELF_ERROR.
 */
extern _u32 malelf_binary_create_elf_exec32(MalelfBinary *bin);


/*! Create executable file arch 64.
 *
 *  \param bin A valid MalelfBinary object.
 *
 *  \return MALELF_SUCCESS if the operation succeeded, otherwise MALELF_ERROR.
 */
extern _u32 malelf_binary_create_elf_exec64(MalelfBinary *bin);


/*! Create a executable file.
 *
 *  \param bin A valid MalelfBinary object.
 *  \param class Architeture class of binary.
 *
 *  \return MALELF_SUCCESS if the operation succeeded, otherwise MALELF_ERROR.
 */
extern _u32 malelf_binary_create_elf_exec(MalelfBinary *bin, _u8 class);


/*! Add a Program Header Table.
 *
 *  \param bin A valid MalelfBinary object.
 *  \param phdr The new phdr.
 *
 *  \return MALELF_SUCCESS if the operation succeeded, otherwise MALELF_ERROR.
 */
extern _u32 malelf_binary_add_phdr32(MalelfBinary *bin, Elf32_Phdr *phdr);



#endif /* MALELF_BINARY_H */
