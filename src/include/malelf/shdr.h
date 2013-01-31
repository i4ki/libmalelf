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
        _u8 class;          /*!< Architeture class */
} MalelfShdr;

typedef struct {
	char *name;
	_u16 type;
	_u32 offset;
	_u32 size;
	MalelfShdr *shdr;
} MalelfSection;

MALELF_END_DECLS


#endif /* MALELF_PHDR_H */
