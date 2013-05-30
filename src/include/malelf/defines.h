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
 * Contributors:
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

/* Binary format type */
#define MALELF_FMT_ELF (0)
#define MALELF_FMT_FLAT (1)

/* Binary format types + architecture */
#       define MALELF_ELF ELFCLASSNONE
        /* ELF Architecture Type */
#       define MALELF_ELFNONE MALELF_ELF
#       define MALELF_ELF32 ELFCLASS32
#       define MALELF_ELF64 ELFCLASS64

#       define MALELF_FLAT (1 + MALELF_ELF64)
        /* Flat Architecture Type */
#       define MALELF_FLATUNKNOWN MALELF_FLAT
#       define MALELF_FLAT32 (1 + MALELF_FLATUNKNOWN)
#       define MALELF_FLAT64 (1 + MALELF_FLAT32)


/* System-function used to allocate buffer */
#define MALELF_ALLOC_NONE 0
#define MALELF_ALLOC_MMAP 1
#define MALELF_ALLOC_MALLOC 2

#define MALELF_ORIGIN (0x08048000)

#define MALELF_ELF_DATA(hdr) \
        ( \
                (hdr)->class == MALELF_ELF32 ?        \
                (void *)((hdr)->uhdr.h32) :        \
                ( \
                        (hdr)->class == MALELF_ELF64 ? \
                        (void *)((hdr)->uhdr.h64) :    \
                        NULL \
                ) \
        )

#define MALELF_ELF_FIELD(hdr, field, error)  \
        (((hdr)->class == MALELF_ELF32) ?      \
                ((hdr)->uhdr.h32->field) :                \
        (((hdr)->class == MALELF_ELF64) ? \
                ((hdr)->uhdr.h64->field) : (error = MALELF_EINVALID_CLASS) && NULL))

#define MALELF_MAGIC_BYTES 0x37333331
#define MALELF_PAGE_SIZE (4096)

#endif /* MALELF_DEFINES_H */
