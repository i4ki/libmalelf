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

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <elf.h>

#include <malelf/types.h>
#include <malelf/error.h>
#include <malelf/defines.h>
#include <malelf/phdr.h>


_u32 malelf_phdr_get_type(MalelfPhdr *phdr, _u32 *type, _u32 index)
{
        Elf32_Phdr *phdr32;
        Elf64_Phdr *phdr64;

        switch(phdr->class) {
        case MALELF_ELF32:
                phdr32 = phdr->uhdr.h32 + index;
                *type = phdr32->p_type;
                break;
        case MALELF_ELF64:
                phdr64 = phdr->uhdr.h64 + index;
                *type = phdr64->p_type;
                break;
        default: return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_phdr_get_offset(MalelfPhdr *phdr, _u32 *offset, _u32 index)
{
        Elf32_Phdr *phdr32;
        Elf64_Phdr *phdr64;

        switch(phdr->class) {
        case MALELF_ELF32:
                phdr32 = phdr->uhdr.h32 + index;
                *offset = phdr32->p_offset;
                break;
        case MALELF_ELF64:
                phdr64 = phdr->uhdr.h64 + index;
                *offset = phdr64->p_offset;
                break;
        default: return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_phdr_get_vaddr(MalelfPhdr *phdr, _u32 *vaddr, _u32 index)
{
        Elf32_Phdr *phdr32;
        Elf64_Phdr *phdr64;

        switch(phdr->class) {
        case MALELF_ELF32:
                phdr32 = phdr->uhdr.h32 + index;
                *vaddr = phdr32->p_vaddr;
                break;
        case MALELF_ELF64:
                phdr64 = phdr->uhdr.h64 + index;
                *vaddr = phdr64->p_vaddr;
                break;
        default: return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_phdr_get_paddr(MalelfPhdr *phdr, _u32 *paddr, _u32 index)
{
        Elf32_Phdr *phdr32;
        Elf64_Phdr *phdr64;

        switch(phdr->class) {
        case MALELF_ELF32:
                phdr32 = phdr->uhdr.h32 + index;
                *paddr = phdr32->p_paddr;
                break;
        case MALELF_ELF64:
                phdr64 = phdr->uhdr.h64 + index;
                *paddr = phdr64->p_paddr;
                break;
        default: return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_phdr_get_filesz(MalelfPhdr *phdr, _u32 *filesz, _u32 index)
{
        Elf32_Phdr *phdr32;
        Elf64_Phdr *phdr64;

        switch(phdr->class) {
        case MALELF_ELF32:
                phdr32 = phdr->uhdr.h32 + index;
                *filesz = phdr32->p_filesz;
                break;
        case MALELF_ELF64:
                phdr64 = phdr->uhdr.h64 + index;
                *filesz = phdr64->p_filesz;
                break;
        default: return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_phdr_dump(Elf32_Phdr *p)
{
        malelf_success("p_type: %u\n", p->p_type);
        malelf_success("p_offset: 0x%08x\n", p->p_offset);
        malelf_success("p_vaddr: 0x%08x\n", p->p_vaddr);

        malelf_success("Dump:\n");
        return malelf_dump((_u8 *) p, sizeof (Elf32_Phdr));
}

_u32 malelf_phdr_get_memsz(MalelfPhdr *phdr, _u32 *memsz, _u32 index)
{
        Elf32_Phdr *phdr32;
        Elf64_Phdr *phdr64;

        switch(phdr->class) {
        case MALELF_ELF32:
                phdr32 = phdr->uhdr.h32 + index;
                *memsz = phdr32->p_memsz;
                break;
        case MALELF_ELF64:
                phdr64 = phdr->uhdr.h64 + index;
                *memsz = phdr64->p_memsz;
                break;
        default: return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}


_u32 malelf_phdr_get_flags(MalelfPhdr *phdr, _u32 *flags, _u32 index)
{
        Elf32_Phdr *phdr32;
        Elf64_Phdr *phdr64;

        switch(phdr->class) {
        case MALELF_ELF32:
                phdr32 = phdr->uhdr.h32 + index;
                *flags = phdr32->p_flags;
                break;
        case MALELF_ELF64:
                phdr64 = phdr->uhdr.h64 + index;
                *flags = phdr64->p_flags;
                break;
        default: return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_phdr_get_align(MalelfPhdr *phdr, _u32 *align, _u32 index)
{
        Elf32_Phdr *phdr32;
        Elf64_Phdr *phdr64;

        switch(phdr->class) {
        case MALELF_ELF32:
                phdr32 = phdr->uhdr.h32 + index;
                *align = phdr32->p_align;
                break;
        case MALELF_ELF64:
                phdr64 = phdr->uhdr.h64 + index;
                *align = phdr64->p_align;
                break;
        default: return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}
