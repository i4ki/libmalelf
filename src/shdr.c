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
#include <malelf/shdr.h>

static MalelfShdrType _shdr_type[] = {
        {"SHT_NULL", SHT_NULL, "Section header table entry unused "},
        {"SHT_PROGBITS", SHT_PROGBITS, "Program data "},
        {"SHT_SYMTAB", SHT_SYMTAB, "Symbol table "},
        {"SHT_STRTAB", SHT_STRTAB, "String table "},
        {"SHT_RELA", SHT_RELA, "Relocation entries with addends "},
        {"SHT_HASH", SHT_HASH, "Symbol hash table "},
        {"SHT_DYNAMIC", SHT_DYNAMIC, "Dynamic linking information "},
        {"SHT_NOTE", SHT_NOTE, "Notes "},
        {"SHT_NOBITS", SHT_NOBITS, "Program space with no data (bss) "},
        {"SHT_REL", SHT_REL, "Relocation entries, no addends "},
        {"SHT_SHLIB", SHT_SHLIB, "Reserved "},
        {"SHT_DYNSYM", SHT_DYNSYM, "Dynamic linker symbol table "},
        {"SHT_INIT_ARRAY", SHT_INIT_ARRAY, "Array of constructors "},
        {"SHT_FINI_ARRAY", SHT_FINI_ARRAY, "Array of destructors "},
        {"SHT_PREINIT_ARRAY", SHT_PREINIT_ARRAY, "Array of pre-constructors "},
        {"SHT_GROUP", SHT_GROUP, "Section group "},
        {"SHT_SYMTAB_SHNDX", SHT_SYMTAB_SHNDX, "Extended section indeces "},
        {"SHT_NUM", SHT_NUM, "Number of defined types.  "},
        {"SHT_LOOS", SHT_LOOS, "Start OS-specific.  "},
        {"SHT_GNU_ATTRIBUTES", SHT_GNU_ATTRIBUTES, "Object attributes.  "},
        {"SHT_GNU_HASH", SHT_GNU_HASH, "GNU-style hash table.  "},
        {"SHT_GNU_LIBLIST", SHT_GNU_LIBLIST, "Prelink library list "},
        {"SHT_CHECKSUM", SHT_CHECKSUM, "Checksum for DSO content.  "},
        {"SHT_LOSUNW", SHT_LOSUNW, "Sun-specific low bound.  "},
        {"SHT_SUNW_move", SHT_SUNW_move, "SunW "},
        {"SHT_SUNW_COMDAT", SHT_SUNW_COMDAT, "SunW COMDAT "},
        {"SHT_SUNW_syminfo", SHT_SUNW_syminfo, "SunW SYNINFO "},
        {"SHT_GNU_verdef", SHT_GNU_verdef, "Version definition section.  "},
        {"SHT_GNU_verneed", SHT_GNU_verneed, "Version needs section.  "},
        {"SHT_GNU_versym", SHT_GNU_versym, "Version symbol table.  "},
        {"SHT_HISUNW", SHT_HISUNW, "Sun-specific high bound.  "},
        {"SHT_HIOS", SHT_HIOS, "End OS-specific type "},
        {"SHT_LOPROC", SHT_LOPROC, "Start of processor-specific "},
        {"SHT_HIPROC", SHT_HIPROC, "End of processor-specific "},
        {"SHT_LOUSER", SHT_LOUSER, "Start of application-specific "},
        {"SHT_HIUSER", SHT_HIUSER, "End of application-specific "}
};

_u32 malelf_shdr_get_type(MalelfShdr *shdr,
                          _u32 *type,
                          _u32 index)
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


_u32 malelf_shdr_get_mstype(MalelfShdr *shdr,
                            MalelfShdrType *ms_type,
                            _u32 index)
{
        _u32 type;
        unsigned int i;

        if (NULL == shdr) {
                return MALELF_ERROR;
        }

        malelf_shdr_get_type(shdr, &type, index);
        for (i = 0; i < sizeof(_shdr_type)/sizeof(MalelfShdrType); i++) {
                if (type == _shdr_type[i].value) {
                        *ms_type = _shdr_type[i];
                        break;
                }
        }

        return MALELF_SUCCESS;
}

_u32 malelf_shdr_get_name(MalelfShdr *shdr,
                          _u32 *name,
                          _u32 index)
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

_u32 malelf_shdr_get_flags(MalelfShdr *shdr,
                           _u32 *flags,
                           _u32 index)
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

_u32 malelf_shdr_get_addr(MalelfShdr *shdr,
                          _u32 *addr,
                          _u32 index)
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

_u32 malelf_shdr_get_offset(MalelfShdr *shdr,
                            _u32 *offset,
                            _u32 index)
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

_u32 malelf_shdr_get_size(MalelfShdr *shdr,
                          _u32 *size,
                          _u32 index)
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

_u32 malelf_shdr_get_link(MalelfShdr *shdr,
                          _u32 *link,
                          _u32 index)
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

_u32 malelf_shdr_get_info(MalelfShdr *shdr,
                          _u32 *info,
                          _u32 index)
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

_u32 malelf_shdr_get_addralign(MalelfShdr *shdr,
                               _u32 *addralign,
                               _u32 index)
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

_u32 malelf_shdr_get_entsize(MalelfShdr *shdr,
                             _u32 *entsize,
                             _u32 index)
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
