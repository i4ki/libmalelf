/*
 * The libmalelf is an evil library that could be used for good! It was
 * developed with the intent to assist in the process of infecting
 * binaries and provide a safe way to analyze malwares.
 *
 * Evil using this library is the responsibility of the programmer.
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

#include <malelf/defines.h>
#include <malelf/types.h>
#include <malelf/error.h>
#include <malelf/ehdr.h>

static MalelfEhdrTable _me_type[] = {
        {"ET_NONE",        0, "No filetype"},
        {"ET_REL",         1, "Relocatable file"},
        {"ET_EXEC",        2, "Executable file"},
        {"ET_DYN",         3, "Shared object file"},
        {"ET_CORE",        4, "Core file"},
        {"ET_LOPROC", 0xff00, "Processor-specific"},
        {"ET_HIPROC", 0xffff, "Processor-specific"},
        {"UNKNOWN", 0, "UNKNOWN"}
};

static MalelfEhdrTable _me_version[] = {
        {"EV_NONE",    0, "Invalid version"},
        {"EV_CURRENT", 1, "Current Version"},
        {"UNKNOWN", 0, "UNKNOWN"}
};

static MalelfEhdrTable _me_machine[] = {
#include "elf_machines.inc"
        {"UNKNOWN", 201, "UNKNOWN"}
};

/* static methods */

static _u32 _malelf_ehdr_get_machine(MalelfEhdr *ehdr, _u8 *machine)
{
        int error = MALELF_SUCCESS;

        assert(NULL != ehdr);

        *machine = MALELF_ELF_FIELD(ehdr, e_machine, error);

        return error;
}



static _u32 _malelf_ehdr_get_type(MalelfEhdr *ehdr, _u16 *type)
{
        int error = MALELF_SUCCESS;
        assert(NULL != ehdr);

        *type = MALELF_ELF_FIELD(ehdr, e_type, error);
        return error;
}

static _u32 _malelf_ehdr_get_version(MalelfEhdr *ehdr, _u8 *version)
{
        int error = MALELF_SUCCESS;
        assert(NULL != ehdr);

        *version = MALELF_ELF_FIELD(ehdr, e_version, error);
        return error;
}

_u32 malelf_ehdr_get_version(MalelfEhdr *ehdr,
                             MalelfEhdrTable *me_version)
{
        int error = MALELF_SUCCESS;
        _u8 version;

        error = _malelf_ehdr_get_version(ehdr, &version);

        if (MALELF_SUCCESS != error) {
                return error;
        }

        switch(version) {
        case EV_NONE:
                *me_version = _me_version[0];
                break;
        case EV_CURRENT:
                *me_version = _me_version[1];
                break;
        default:
                *me_version = _me_version[2];
                me_version->value = version;
                error = MALELF_ERROR;
        }

        return error;
}

_u32 malelf_ehdr_get_type (MalelfEhdr *ehdr,
                           MalelfEhdrTable *me_type)
{
        int error = MALELF_SUCCESS;
        _u16 type;

        error = _malelf_ehdr_get_type(ehdr, &type);

        if (MALELF_SUCCESS != error) {
                me_type = NULL;
                return error;
        }

        switch(type) {
        case ET_NONE:
                *me_type = _me_type[0];
                break;
        case ET_REL:
                *me_type = _me_type[1];
                break;
        case ET_EXEC:
                *me_type = _me_type[2];
                break;
        case ET_DYN:
                *me_type = _me_type[3];
                break;
        case ET_CORE:
                *me_type = _me_type[4];
                break;
        case ET_LOPROC:
                *me_type = _me_type[5];
                break;
        case ET_HIPROC:
                *me_type = _me_type[6];
                break;
        default:
                *me_type = _me_type[7];
                me_type->value = type;
                error = MALELF_ERROR;
        }

        return error;
}



_u32 malelf_ehdr_get_machine(MalelfEhdr *ehdr,
                             MalelfEhdrTable *me_machine)
{
        int error = MALELF_SUCCESS;
        _u8 machine;

        error = _malelf_ehdr_get_machine(ehdr, &machine);

        if (MALELF_SUCCESS != error) {
                return error;
        }

        switch(machine) {
        case EM_NONE:
                *me_machine = _me_machine[0];
                break;
        case EM_M32:
                *me_machine = _me_machine[1];
                break;
        case EM_SPARC:
                *me_machine = _me_machine[2];
                break;
        case EM_386:
                *me_machine = _me_machine[3];
                break;
        case EM_68K:
                *me_machine = _me_machine[4];
                break;
        case EM_88K:
                *me_machine = _me_machine[5];
                break;
        case EM_860:
                *me_machine = _me_machine[6];
                break;
        case EM_MIPS:
                *me_machine = _me_machine[7];
                break;
        default:
                *me_machine = _me_machine[8];
                me_machine->value = machine;
                error = MALELF_ERROR;
        }

        return error;
}


_u32 malelf_ehdr_get_entry(MalelfEhdr *ehdr, _u32 *entry)
{
        int error = MALELF_SUCCESS;

        *entry = MALELF_ELF_FIELD(ehdr, e_entry, error);

        return error;
}

_u32 malelf_ehdr_get_phoff(MalelfEhdr *ehdr, _u32 *phoff)
{
        int error = MALELF_SUCCESS;

        *phoff = MALELF_ELF_FIELD(ehdr, e_phoff, error);
        return error;
}

_u32 malelf_ehdr_get_shoff(MalelfEhdr *ehdr, _u32 *shoff)
{
        int error = MALELF_SUCCESS;
        *shoff = MALELF_ELF_FIELD(ehdr, e_shoff, error);
        return error;
}

_u32 malelf_ehdr_get_ehsize(MalelfEhdr *ehdr, _u32 *size)
{
        int error = MALELF_SUCCESS;

        *size = MALELF_ELF_FIELD(ehdr, e_ehsize, error);
        return error;
}


_u32 malelf_ehdr_get_phentsize(MalelfEhdr *ehdr, _u32 *phentsize)
{
        int error = MALELF_SUCCESS;
        *phentsize = MALELF_ELF_FIELD(ehdr, e_phentsize, error);
        return error;
}


_u32 malelf_ehdr_get_phnum(MalelfEhdr *ehdr, _u32 *phnum)
{
        int error = MALELF_SUCCESS;
        assert(ehdr != NULL);
        *phnum = MALELF_ELF_FIELD(ehdr, e_phnum, error);
        return MALELF_SUCCESS;
}


_u32 malelf_ehdr_get_shentsize(MalelfEhdr *ehdr, _u32 *shentsize)
{
        int error = MALELF_SUCCESS;
        assert(NULL != ehdr);

        *shentsize = MALELF_ELF_FIELD(ehdr, e_shentsize, error);
        return error;
}


_u32 malelf_ehdr_get_shnum(MalelfEhdr *ehdr, _u32 *shnum)
{
        int error = MALELF_SUCCESS;
        assert(NULL != ehdr);

        *shnum = MALELF_ELF_FIELD(ehdr, e_shnum, error);
        return error;
}


_u32 malelf_ehdr_get_shstrndx(MalelfEhdr *ehdr, _u32 *shstrndx)
{
        int error = MALELF_SUCCESS;
        assert(NULL != ehdr);

        *shstrndx = MALELF_ELF_FIELD(ehdr, e_shstrndx, error);

        return error;
}

_u32 malelf_ehdr_get_flags(MalelfEhdr *ehdr, _u32 *flags)
{
        int error = MALELF_SUCCESS;
        assert(NULL != ehdr);

        *flags = MALELF_ELF_FIELD(ehdr, e_flags, error);
        return error;
}

_u32 malelf_ehdr_set(MalelfEhdr* ehdr, _u8 *mem, _u32 size)
{
        assert(NULL != ehdr);
        assert(NULL != mem);

        switch (ehdr->class) {
        case MALELF_ELF32:
                if (size > sizeof(Elf32_Ehdr)) {
                        return MALELF_EEHDR_OVERFLOW;
                }

                memcpy(ehdr->uhdr.h32, mem, size);
                break;
        case MALELF_ELF64:
                if (size > sizeof(Elf64_Ehdr)) {
                        return MALELF_EEHDR_OVERFLOW;
                }

                memcpy(ehdr->uhdr.h64, mem, size);
                break;
        default:
                return MALELF_EINVALID_CLASS;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_ehdr_set_entry(MalelfEhdr *ehdr, _u32 new_entry)
{
        _u32 error = MALELF_SUCCESS;

        switch (ehdr->class) {
        case MALELF_ELF32:
                ehdr->uhdr.h32->e_entry = new_entry;
                break;
        case MALELF_ELF64:
                ehdr->uhdr.h64->e_entry = new_entry;
                break;
        default:
                error = MALELF_EINVALID_CLASS;
        }

        return error;
}

_u32 malelf_ehdr_set_ehsize(MalelfEhdr *ehdr, _u32 ehsize)
{
        _u32 error = MALELF_SUCCESS;

        switch (ehdr->class) {
        case MALELF_ELF32:
                ehdr->uhdr.h32->e_ehsize = ehsize;
                break;
        case MALELF_ELF64:
                ehdr->uhdr.h64->e_ehsize = ehsize;
                break;
        default:
                error = MALELF_EINVALID_CLASS;
        }

        return error;
}

_u32 malelf_ehdr_set_phoff(MalelfEhdr *ehdr, _u32 phoff)
{
        _u32 error = MALELF_SUCCESS;

        switch (ehdr->class) {
        case MALELF_ELF32:
                ehdr->uhdr.h32->e_phoff = phoff;
                break;
        case MALELF_ELF64:
                ehdr->uhdr.h64->e_phoff = phoff;
                break;
        default:
                error = MALELF_EINVALID_CLASS;
        }

        return error;
}

_u32 malelf_ehdr_set_phnum(MalelfEhdr *ehdr, _u32 phnum)
{
        _u32 error = MALELF_SUCCESS;

        switch (ehdr->class) {
        case MALELF_ELF32:
                ehdr->uhdr.h32->e_phnum = phnum;
                break;
        case MALELF_ELF64:
                ehdr->uhdr.h64->e_phnum = phnum;
                break;
        default:
                error = MALELF_EINVALID_CLASS;
        }

        return error;
}

_u32 malelf_ehdr_set_shoff(MalelfEhdr *ehdr, _u32 shoff)
{
        _u32 error = MALELF_SUCCESS;

        switch (ehdr->class) {
        case MALELF_ELF32:
                ehdr->uhdr.h32->e_shoff = shoff;
                break;
        case MALELF_ELF64:
                ehdr->uhdr.h64->e_shoff = shoff;
                break;
        default:
                error = MALELF_EINVALID_CLASS;
        }

        return error;
}

_u32 malelf_ehdr_set_shnum(MalelfEhdr *ehdr, _u32 shnum)
{
        _u32 error = MALELF_SUCCESS;

        switch (ehdr->class) {
        case MALELF_ELF32:
                ehdr->uhdr.h32->e_shnum = shnum;
                break;
        case MALELF_ELF64:
                ehdr->uhdr.h64->e_shnum = shnum;
                break;
        default:
                error = MALELF_EINVALID_CLASS;
        }

        return error;
}

_u32 malelf_ehdr_set_phentsize(MalelfEhdr *ehdr, _u32 phentsize)
{
        _u32 error = MALELF_SUCCESS;

        switch (ehdr->class) {
        case MALELF_ELF32:
                ehdr->uhdr.h32->e_phentsize = phentsize;
                break;
        case MALELF_ELF64:
                ehdr->uhdr.h64->e_phentsize = phentsize;
                break;
        default:
                error = MALELF_EINVALID_CLASS;
        }

        return error;
}

_u32 malelf_ehdr_set_shentsize(MalelfEhdr *ehdr, _u32 shentsize)
{
        _u32 error = MALELF_SUCCESS;

        switch (ehdr->class) {
        case MALELF_ELF32:
                ehdr->uhdr.h32->e_shentsize = shentsize;
                break;
        case MALELF_ELF64:
                ehdr->uhdr.h64->e_shentsize = shentsize;
                break;
        default:
                error = MALELF_EINVALID_CLASS;
        }

        return error;
}

_u32 malelf_ehdr_set_shstrndx(MalelfEhdr *ehdr, _u32 shstrndx)
{
        _u32 error = MALELF_SUCCESS;

        switch (ehdr->class) {
        case MALELF_ELF32:
                ehdr->uhdr.h32->e_shstrndx = shstrndx;
                break;
        case MALELF_ELF64:
                ehdr->uhdr.h64->e_shstrndx = shstrndx;
                break;
        default:
                error = MALELF_EINVALID_CLASS;
        }

        return error;
}

_u32 malelf_ehdr_set_version(MalelfEhdr *ehdr, _u32 version)
{
        _u32 error = MALELF_SUCCESS;

        switch (ehdr->class) {
        case MALELF_ELF32:
                ehdr->uhdr.h32->e_version = version;
                break;
        case MALELF_ELF64:
                ehdr->uhdr.h64->e_version = version;
                break;
        default:
                error = MALELF_EINVALID_CLASS;
        }

        return error;
}

_u32 malelf_ehdr_set_type(MalelfEhdr *ehdr, _u32 type)
{
        _u32 error = MALELF_SUCCESS;

        switch (ehdr->class) {
        case MALELF_ELF32:
                ehdr->uhdr.h32->e_type = type;
                break;
        case MALELF_ELF64:
                ehdr->uhdr.h64->e_type = type;
                break;
        default:
                error = MALELF_EINVALID_CLASS;
        }

        return error;
}
