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
#include <malelf/shdr.h>


_u32 malelf_shdr_get_name(MalelfShdr *shdr, _u32 *name, _u32 index)
{
        Elf32_Shdr *shdr32;
        Elf64_Shdr *shdr64;

        switch(shdr->class) {
        case MALELF_ELF32:
                shdr32 = shdr->uhdr.h32 + index;
                *name = shdr32->sh_name;
                break;
        case MALELF_ELF64:
                shdr64 = shdr->uhdr.h64 + index;
                *name = shdr64->sh_name;
                break;
        default: return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_shdr_get_type(MalelfShdr *shdr, _u32 *type, _u32 index)
{
        Elf32_Shdr *shdr32;
        Elf64_Shdr *shdr64;

        switch(shdr->class) {
        case MALELF_ELF32:
                shdr32 = shdr->uhdr.h32 + index;
                *type = shdr32->sh_type;
                break;
        case MALELF_ELF64:
                shdr64 = shdr->uhdr.h64 + index;
                *type = shdr64->sh_type;
                break;
        default: return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_shdr_get_flags(MalelfShdr *shdr, _u32 *flags, _u32 index)
{
        Elf32_Shdr *shdr32;
        Elf64_Shdr *shdr64;

        switch(shdr->class) {
        case MALELF_ELF32:
                shdr32 = shdr->uhdr.h32 + index;
                *flags = shdr32->sh_flags;
                break;
        case MALELF_ELF64:
                shdr64 = shdr->uhdr.h64 + index;
                *flags = shdr64->sh_flags;
                break;
        default: return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_shdr_get_addr(MalelfShdr *shdr, _u32 *addr, _u32 index)
{
        Elf32_Shdr *shdr32;
        Elf64_Shdr *shdr64;

        switch(shdr->class) {
        case MALELF_ELF32:
                shdr32 = shdr->uhdr.h32 + index;
                *addr = shdr32->sh_addr;
                break;
        case MALELF_ELF64:
                shdr64 = shdr->uhdr.h64 + index;
                *addr = shdr64->sh_addr;
                break;
        default: return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_shdr_get_offset(MalelfShdr *shdr, _u32 *offset, _u32 index)
{
        Elf32_Shdr *shdr32;
        Elf64_Shdr *shdr64;

        switch(shdr->class) {
        case MALELF_ELF32:
                shdr32 = shdr->uhdr.h32 + index;
                *offset = shdr32->sh_offset;
                break;
        case MALELF_ELF64:
                shdr64 = shdr->uhdr.h64 + index;
                *offset = shdr64->sh_offset;
                break;
        default: return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_shdr_get_size(MalelfShdr *shdr, _u32 *size, _u32 index)
{
        Elf32_Shdr *shdr32;
        Elf64_Shdr *shdr64;

        switch(shdr->class) {
        case MALELF_ELF32:
                shdr32 = shdr->uhdr.h32 + index;
                *size = shdr32->sh_size;
                break;
        case MALELF_ELF64:
                shdr64 = shdr->uhdr.h64 + index;
                *size = shdr64->sh_size;
                break;
        default: return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_shdr_get_link(MalelfShdr *shdr, _u32 *link, _u32 index)
{
        Elf32_Shdr *shdr32;
        Elf64_Shdr *shdr64;

        switch(shdr->class) {
        case MALELF_ELF32:
                shdr32 = shdr->uhdr.h32 + index;
                *link = shdr32->sh_link;
                break;
        case MALELF_ELF64:
                shdr64 = shdr->uhdr.h64 + index;
                *link = shdr64->sh_link;
                break;
        default: return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_shdr_get_info(MalelfShdr *shdr, _u32 *info, _u32 index)
{
        Elf32_Shdr *shdr32;
        Elf64_Shdr *shdr64;

        switch(shdr->class) {
        case MALELF_ELF32:
                shdr32 = shdr->uhdr.h32 + index;
                *info = shdr32->sh_info;
                break;
        case MALELF_ELF64:
                shdr64 = shdr->uhdr.h64 + index;
                *info = shdr64->sh_info;
                break;
        default: return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_shdr_get_addralign(MalelfShdr *shdr, _u32 *addralign, _u32 index)
{
        Elf32_Shdr *shdr32;
        Elf64_Shdr *shdr64;

        switch(shdr->class) {
        case MALELF_ELF32:
                shdr32 = shdr->uhdr.h32 + index;
                *addralign = shdr32->sh_addralign;
                break;
        case MALELF_ELF64:
                shdr64 = shdr->uhdr.h64 + index;
                *addralign = shdr64->sh_addralign;
                break;
        default: return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_shdr_get_entsize(MalelfShdr *shdr, _u32 *entsize, _u32 index)
{
        Elf32_Shdr *shdr32;
        Elf64_Shdr *shdr64;

        switch(shdr->class) {
        case MALELF_ELF32:
                shdr32 = shdr->uhdr.h32 + index;
                *entsize = shdr32->sh_entsize;
                break;
        case MALELF_ELF64:
                shdr64 = shdr->uhdr.h64 + index;
                *entsize = shdr64->sh_entsize;
                break;
        default: return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

