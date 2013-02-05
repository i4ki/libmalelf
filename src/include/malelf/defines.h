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

#ifndef MALELF_DEFINES_H
#define MALELF_DEFINES_H

#ifdef __cplusplus
# define MALELF_BEGIN_DECLS extern "C" {
# define MALELF_END_DECLS }
#else
# define MALELF_BEGIN_DECLS /* empty */
# define MALELF_END_DECLS /* empty */
#endif

/* Unused variables */
#define UNUSED(x) (void) x

/* ELF Architecture Type */
#define MALELF_ELF32 ELFCLASS32
#define MALELF_ELF64 ELFCLASS64
#define MALELF_ELFNONE ELFCLASSNONE

/* System-function used to allocate buffer */
#define MALELF_ALLOC_NONE 0
#define MALELF_ALLOC_MMAP 1
#define MALELF_ALLOC_MALLOC 2

#define MALELF_ELF_DATA(hdr) \
        ( \
                (hdr)->class == MALELF_ELF32 ?	\
		(void *)((hdr)->uhdr.h32) :	\
                ( \
                        (hdr)->class == MALELF_ELF64 ? \
                        (void *)((hdr)->uhdr.h64) :    \
		        NULL \
		) \
	)

#define MALELF_ELF_FIELD(hdr, field, error)  \
        (((hdr)->class == MALELF_ELF32) ?      \
	        ((hdr)->uhdr.h32->field) :		\
        (((hdr)->class == MALELF_ELF64) ? \
	        ((hdr)->uhdr.h64->field) : (error = MALELF_EINVALID_CLASS) && NULL))

#define MALELF_ELF(bin, hdr, field, error)                    \
  MALELF_HDR((&(bin)->elf.hdr), (bin)->class, field, error)

#endif /* MALELF_DEFINES_H */
