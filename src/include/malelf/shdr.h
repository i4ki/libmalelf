/* 
 * The malelf library was written in pure C, with the objective to 
 * provide a quick and easy way a set functions for programmers to 
 * manipulate ELF files. With libmalelf can dissect and infect ELF 
 * files. Evil using this library is the responsibility of the programmer.
 *
 * Author: Tiago Natel de Moura <tiago4orion@gmail.com>
 *
 * Contributor: Daniel Ricardo dos Santos <danielricardo.santos@gmail.com>
 *              Paulo Leonardo Benatto <benatto@gmail.com>
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
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef MALELF_SHDR_H
#define MALELF_SHDR_H

#include <elf.h>

#include "types.h"

MALELF_BEGIN_DECLS

#define MALELF_SHDR_SIZE(class) \
	((class == MALELF_ELF32) ? sizeof (Elf32_Shdr) : sizeof (Elf64_Shdr))

/*!
 * \file phdr.h
 * \brief A class used to control the section header table.
 *
 * The MalelfShdr union is an opaque data type. It
 * should only be accessed via the following functions. 
 *
 */

typedef struct {
	union {
		Elf32_Shdr *h32;    /*!< 32-bits ELF Section Headers */
		Elf64_Shdr *h64;    /*!< 64-bits ELF Section Headers */
	} uhdr;
    _u8 class;
} MalelfShdr;

typedef struct {
	char *name;
	_u16 type;
	_u32 offset;
	_u32 size;
	MalelfShdr *shdr;
} MalelfSection;


/*! Get sh_name member from Section Header Table.
 *  
 *  \param shdr A valid MalelfShdr object.
 *  \param name The sh_name saved.
 *  \param index The index of section.
 *
 *  \return MALELF_SUCCESS if name was successful set, 
 *          otherwise returns MALELF_ERROR.  
 */
extern _u32 malelf_shdr_get_name(MalelfShdr *shdr, _u32 *name, _u32 index);


/*! Get sh_type member from Section Header Table.
 *  
 *  \param shdr A valid MalelfShdr object.
 *  \param type The sh_type saved.
 *  \param index The index of section.
 *
 *  \return MALELF_SUCCESS if type was successful set, 
 *          otherwise returns MALELF_ERROR.  
 */
extern _u32 malelf_shdr_get_type(MalelfShdr *shdr, _u32 *type, _u32 index);


/*! Get sh_flags member from Section Header Table.
 *  
 *  \param shdr A valid MalelfShdr object.
 *  \param flags The sh_flags saved.
 *  \param index The index of section.
 *
 *  \return MALELF_SUCCESS if flags was successful set, 
 *          otherwise returns MALELF_ERROR.  
 */
extern _u32 malelf_shdr_get_flags(MalelfShdr *shdr, _u32 *flags, _u32 index);


/*! Get sh_addr member from Section Header Table.
 *  
 *  \param shdr A valid MalelfShdr object.
 *  \param addr The sh_addr saved.
 *  \param index The index of section.
 *
 *  \return MALELF_SUCCESS if addr was successful set, 
 *          otherwise returns MALELF_ERROR.  
 */
extern _u32 malelf_shdr_get_addr(MalelfShdr *shdr, _u32 *addr, _u32 index);


/*! Get sh_offset member from Section Header Table.
 *  
 *  \param shdr A valid MalelfShdr object.
 *  \param offset The sh_offset saved.
 *  \param index The index of section.
 *
 *  \return MALELF_SUCCESS if offset was successful set, 
 *          otherwise returns MALELF_ERROR.  
 */
extern _u32 malelf_shdr_get_offset(MalelfShdr *shdr, _u32 *offset, _u32 index);


/*! Get sh_size member from Section Header Table.
 *  
 *  \param shdr A valid MalelfShdr object.
 *  \param size The sh_size saved.
 *  \param index The index of section.
 *
 *  \return MALELF_SUCCESS if size was successful set, 
 *          otherwise returns MALELF_ERROR.  
 */
extern _u32 malelf_shdr_get_size(MalelfShdr *shdr, _u32 *size, _u32 index);


/*! Get sh_link member from Section Header Table.
 *  
 *  \param shdr A valid MalelfShdr object.
 *  \param link The sh_link saved.
 *  \param index The index of section.
 *
 *  \return MALELF_SUCCESS if link was successful set, 
 *          otherwise returns MALELF_ERROR.  
 */
extern _u32 malelf_shdr_get_link(MalelfShdr *shdr, _u32 *link, _u32 index);


/*! Get sh_info member from Section Header Table.
 *  
 *  \param shdr A valid MalelfShdr object.
 *  \param info The sh_info saved.
 *  \param index The index of section.
 *
 *  \return MALELF_SUCCESS if info was successful set, 
 *          otherwise returns MALELF_ERROR.  
 */
extern _u32 malelf_shdr_get_info(MalelfShdr *shdr, _u32 *info, _u32 index);


/*! Get sh_addralign member from Section Header Table.
 *  
 *  \param shdr A valid MalelfShdr object.
 *  \param addralign The sh_addralign saved.
 *  \param index The index of section.
 *
 *  \return MALELF_SUCCESS if addralign was successful set, 
 *          otherwise returns MALELF_ERROR.  
 */
extern _u32 malelf_shdr_get_addralign(MalelfShdr *shdr, 
                                      _u32 *addralign, 
                                      _u32 index);


/*! Get sh_entsize member from Section Header Table.
 *  
 *  \param shdr A valid MalelfShdr object.
 *  \param entsize The sh_entsize saved.
 *  \param index The index of section.
 *
 *  \return MALELF_SUCCESS if entsize was successful set, 
 *          otherwise returns MALELF_ERROR.  
 */
extern _u32 malelf_shdr_get_entsize(MalelfShdr *shdr, 
                                    _u32 *entsize, 
                                    _u32 index);


MALELF_END_DECLS


#endif /* MALELF_PHDR_H */
