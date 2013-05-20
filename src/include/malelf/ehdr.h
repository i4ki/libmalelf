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

#ifndef MALELF_EHDR_H
#define MALELF_EHDR_H

#include <elf.h>

#include "defines.h"
#include "types.h"

MALELF_BEGIN_DECLS

/*! \file ehdr.h
 *  \brief MalelfEhdr class stores information about ELF Header Table.
 *
 *  The MalelfEhdr structure will be responsible to store all information
 *  about ELF Header Table, like object type, version, entry point,
 *  program header table offset, section header table offset, ELF
 *  header size and others.
 *
 *  The MalelfEhdr class is not an opaque data structure, but if you
 *  prefer, there is getters to access the class members.
 *
 */

typedef struct {
        union {
                Elf32_Ehdr *h32;    /*!< 32-bits ELF Header */
                Elf64_Ehdr *h64;    /*!< 64-bits ELF Header */
        } uhdr;
        _u8 class;          /*!< Architeture class */
}MalelfEhdr;

/*! The MalelfEhdrTable stores information about e_type,
 *  e_machine and e_version member.
 */
typedef struct {
        _u16 name;
        _i32 value;
        char *meaning;
} MalelfEhdrTable;

/*! Get e_type member from ELF Header Table.
 *
 *  \param ehdr Valid ELF Header Table object.
 *  \param me_type Saved values(name, valeu and meaning) MalelfEhdrTable.
 *
 *  \return MALELF_SUCCESS if MalelfEhdrTable was successful set,
 *          otherwise returns MALELF_ERROR.
 */
extern _i32 malelf_ehdr_get_type (MalelfEhdr *ehdr,
                                  MalelfEhdrTable *me_type);


/*! Get e_machine member from ELF Header Table.
 *
 *  \param ehdr Valid ELF Header Table object.
 *  \param me_machine Saved values(name, valeu and meaning) MalelfEhdrTable.
 *
 *  \return MALELF_SUCCESS if MalelfEhdrTable was successful set,
 *          otherwise returns MALELF_ERROR.
 */
extern _i32 malelf_ehdr_get_machine(MalelfEhdr *ehdr,
                                    MalelfEhdrTable *me_machine);


/*! Get e_version member from ELF Header Table.
 *
 *  \param ehdr Valid ELF Header Table object.
 *  \param me_version Saved values(name, valeu and meaning) MalelfEhdrTable.
 *
 *  \return MALELF_SUCCESS if MalelfEhdrTable was successful set,
 *          otherwise returns MALELF_ERROR.
 */
extern _i32 malelf_ehdr_get_version(MalelfEhdr *ehdr,
                                    MalelfEhdrTable *version);


/*! Get e_shoff member from ELF Header Table.
 *
 *  \param ehdr Valid ELF Header Table object.
 *  \param shoff Saved e_shoff from ELF Header Table.
 *
 *  \return MALELF_SUCCESS if shoff was successful saved,
 *          otherwise returns MALELF_ERROR.
 */
extern _i32 malelf_ehdr_get_shoff(MalelfEhdr *ehdr,
                                  _u32 *shoff);


/*! Get e_phoff member from ELF Header Table.
 *
 *  \param ehdr Valid ELF Header Table object.
 *  \param phoff Saved e_phoff from ELF Header Table.
 *
 *  \return MALELF_SUCCESS if phoff was successful saved,
 *          otherwise returns MALELF_ERROR.
 */
extern _i32 malelf_ehdr_get_phoff(MalelfEhdr *ehdr,
                                  _u32 *pshoff);


/*! Get e_phoff member from ELF Header Table.
 *
 *  \param ehdr Valid ELF Header Table object.
 *  \param entry Saved e_phoff from ELF Header Table.
 *
 *  \return MALELF_SUCCESS if entry was successful saved,
 *          otherwise returns MALELF_ERROR.
 */
extern _i32 malelf_ehdr_get_entry(MalelfEhdr *ehdr,
                                  _u32 *entry);


/*! Set another Ehdr to the Binary.
 *
 *  \param ehdr Valid ELF Header Table object.
 *  \param mem The new ELF Header Table.
 *  \param size The size of new Ehdr.
 *
 *  \return MALELF_SUCCESS if entry was successful saved,
 *          otherwise returns MALELF_ERROR.
 */
extern _i32 malelf_ehdr_set(MalelfEhdr* ehdr,
                            _u8 *mem,
                            _u32 size);


/*! Get e_ehsize member from ELF Header Table.
 *
 *  \param ehdr Valid ELF Header Table object.
 *  \param ehsize Saved e_ehsize from ELF Header Table.
 *
 *  \return MALELF_SUCCESS if ehsize was successful saved,
 *          otherwise returns MALELF_ERROR.
 */
extern _i32 malelf_ehdr_get_ehsize(MalelfEhdr *ehdr,
                                   _u32 *ehsize);


/*! Get e_phentsize member from ELF Header Table.
 *
 *  \param ehdr Valid ELF Header Table object.
 *  \param phentsize Saved e_phentsize from ELF Header Table.
 *
 *  \return MALELF_SUCCESS if phentsize was successful saved,
 *          otherwise returns MALELF_ERROR.
 */
extern _i32 malelf_ehdr_get_phentsize(MalelfEhdr *ehdr,
                                      _u32 *phentsize);


/*! Get e_phnum member from ELF Header Table.
 *
 *  \param ehdr Valid ELF Header Table object.
 *  \param phnum Saved e_phnum from ELF Header Table.
 *
 *  \return MALELF_SUCCESS if phnum was successful saved,
 *          otherwise returns MALELF_ERROR.
 */
extern _i32 malelf_ehdr_get_phnum(MalelfEhdr *ehdr,
                                  _u32 *phnum);


/*! Get e_shentsize member from ELF Header Table.
 *
 *  \param ehdr Valid ELF Header Table object.
 *  \param shentsize Saved e_shentsize from ELF Header Table.
 *
 *  \return MALELF_SUCCESS if shentsize was successful saved,
 *          otherwise returns MALELF_ERROR.
 */
extern _i32 malelf_ehdr_get_shentsize(MalelfEhdr *ehdr,
                                      _u32 *shentsize);


/*! Get e_shnum member from ELF Header Table.
 *
 *  \param ehdr Valid ELF Header Table object.
 *  \param shnum Saved e_shnum from ELF Header Table.
 *
 *  \return MALELF_SUCCESS if shnum was successful saved,
 *          otherwise returns MALELF_ERROR.
 */
extern _i32 malelf_ehdr_get_shnum(MalelfEhdr *ehdr,
                                  _u32 *shnum);


/*! Get e_shstrndx member from ELF Header Table.
 *
 *  \param ehdr Valid ELF Header Table object.
 *  \param shstrndx Saved e_shstrndx from ELF Header Table.
 *
 *  \return MALELF_SUCCESS if shstrndx was successful saved,
 *          otherwise returns MALELF_ERROR.
 */
extern _i32 malelf_ehdr_get_shstrndx(MalelfEhdr *ehdr,
                                     _u32 *shstrndx);


/*! Get e_flags member from ELF Header Table.
 *
 *  \param ehdr Valid ELF Header Table object.
 *  \param flags Saved e_flags from ELF Header Table.
 *
 *  \return MALELF_SUCCESS if flags was successful saved,
 *          otherwise returns MALELF_ERROR.
 */
extern _i32 malelf_ehdr_get_flags(MalelfEhdr *ehdr,
                                  _u32 *flags);


/*! Set e_entry member from ELF Header Table.
 *
 *  \param ehdr Valid ELF Header Table object.
 *  \param entry The new entry.
 *
 *  \return MALELF_SUCCESS if flags was successful saved,
 *          otherwise returns MALELF_ERROR.
 */
extern _u32 malelf_ehdr_set_entry(MalelfEhdr *ehdr,
                                  _u32 new_entry);

MALELF_END_DECLS


#endif /* MALELF_EHDR_H */
