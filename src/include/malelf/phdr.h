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

#ifndef MALELF_PHDR_H
#define MALELF_PHDR_H

#include <elf.h>

#include "types.h"

MALELF_BEGIN_DECLS

#define MALELF_PHDR_SIZE(class) \
	((class == MALELF_ELF32) ? sizeof(Elf32_Phdr) : sizeof(Elf64_Phdr))

/*!
 * \File phdr.h
 * \brief A class used to control the program headers.
 *
 * The MalelfPhdr union is an opaque data type. It
 * should only be accessed via the following functions. 
 *
 */

typedef struct {
	union {
		Elf32_Phdr *h32;    /*!< 32-bits ELF Program Headers */
		Elf64_Phdr *h64;    /*!< 64-bits ELF Program Headers */
	} uhdr;
        _u8 class;          /*!< Architeture class */
}MalelfPhdr;

typedef struct {
	_u32 type;
	_u8 class;
	_u32 index;
	_u8 *mem;
	_u32 offset;
	_u32 size;
	MalelfPhdr *phdr;
} MalelfSegment;


extern _u32 malelf_phdr_dump(Elf32_Phdr *elf_phdr);


/*! Get p_type member from Program Header Table.
 *  
 *  \param phdr A valid MalelfPhdr object.
 *  \param type Type saved.
 *  \param index The index of segment.
 *
 *  \return MALELF_SUCCESS if type was successful set, 
 *          otherwise returns MALELF_ERROR.  
 */
_u32 malelf_phdr_get_type(MalelfPhdr *phdr, _u32 *type, _u32 index);


/*! Get p_offset member from Program Header Table.
 *   
 *  \param phdr A valid MalelfPhdr object.
 *  \param offset Offset saved.
 *  \param index The index of segment.
 *
 *  \return MALELF_SUCCESS if offset was successful set, 
 *          otherwise returns MALELF_ERROR.  
 */
_u32 malelf_phdr_get_offset(MalelfPhdr *phdr, _u32 *offset, _u32 index);


/*! Get p_vaddr member from Program Header Table.
 *   
 *  \param phdr A valid MalelfPhdr object.
 *  \param vaddr Vaddr saved.
 *  \param index The index of segment.
 *
 *  \return MALELF_SUCCESS if vaddr was successful set, 
 *          otherwise returns MALELF_ERROR.  
 */
_u32 malelf_phdr_get_vaddr(MalelfPhdr *phdr, _u32 *vaddr, _u32 index);


/*! Get p_addr member from Program Header Table.
 *   
 *  \param phdr A valid MalelfPhdr object.
 *  \param paddr Paddr saved.
 *  \param index The index of segment.
 *
 *  \return MALELF_SUCCESS if paddr was successful set, 
 *          otherwise returns MALELF_ERROR.  
 */
_u32 malelf_phdr_get_paddr(MalelfPhdr *phdr, _u32 *paddr, _u32 index);


/*! Get p_filesz member from Program Header Table.
 *   
 *  \param phdr A valid MalelfPhdr object.
 *  \param filesz Filesz saved.
 *  \param index The index of segment.
 *
 *  \return MALELF_SUCCESS if filesz was successful set, 
 *          otherwise returns MALELF_ERROR.  
 */
_u32 malelf_phdr_get_filesz(MalelfPhdr *phdr, _u32 *filesz, _u32 index);


/*! Get p_memsz member from Program Header Table.
 *   
 *  \param phdr A valid MalelfPhdr object.
 *  \param memsz Memsz saved.
 *  \param index The index of segment.
 *
 *  \return MALELF_SUCCESS if memsz was successful set, 
 *          otherwise returns MALELF_ERROR.  
 */
_u32 malelf_phdr_get_memsz(MalelfPhdr *phdr, _u32 *memsz, _u32 index);


/*! Get p_flags member from Program Header Table.
 *   
 *  \param phdr A valid MalelfPhdr object.
 *  \param flags Flags saved.
 *  \param index The index of segment.
 *
 *  \return MALELF_SUCCESS if flags was successful set, 
 *          otherwise returns MALELF_ERROR.  
 */
_u32 malelf_phdr_get_flags(MalelfPhdr *phdr, _u32 *flags, _u32 index);


/*! Get p_align member from Program Header Table.
 *   
 *  \param phdr A valid MalelfPhdr object.
 *  \param align Align saved.
 *  \param index The index of segment.
 *
 *  \return MALELF_SUCCESS if align was successful set, 
 *          otherwise returns MALELF_ERROR.  
 */
_u32 malelf_phdr_get_align(MalelfPhdr *phdr, _u32 *align, _u32 index);


MALELF_END_DECLS


#endif /* MALELF_PHDR_H */
