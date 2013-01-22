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
#include <malelf/ehdr.h>

static MalelfEhdrType _me_type[] = {
        {ET_NONE,        0, "No filetype"},
        {ET_REL,         1, "Relocatable file"},
        {ET_EXEC,        2, "Executable file"},
        {ET_DYN,         3, "Shared object file"},
        {ET_CORE,        4, "Core file"},
        {ET_LOPROC, 0xff00, "Processor-specific"},
        {ET_HIPROC, 0xffff, "Processor-specific"}
};

static MalelfEhdrVersion _me_version[] = {
        {EV_NONE,    0, "Invalid version"},
        {EV_CURRENT, 1, "Current Version"}
};

static MalelfEhdrMachine _me_machine[] = {
        {EM_NONE,  0, "No machine"},
        {EM_M32,   1, "AT&T WE 32100"},
        {EM_SPARC, 2, "SPARC"},
        {EM_386,   3, "Intel 80386"},
        {EM_68K,   4, "Motorola 68000"},
        {EM_88K,   5, "Motorola 88000"},
        {EM_860,   7, "Intel 80860"},
        {EM_MIPS,  8, "MIPS RS3000"}
};

/* static methods */

static _i32 _malelf_ehdr_get_machine(MalelfEhdr *ehdr, _u8 class, _u8 *machine)
{
        assert(NULL != ehdr);
         
        switch(class) {
        case MALELF_ELF32: {
                if (NULL == ehdr->eh32) {
                        return MALELF_ERROR;
                }
                *machine = ehdr->eh32->e_machine;
                return MALELF_SUCCESS;
        } break;

        case MALELF_ELF64: {
                if (NULL == ehdr->eh64) {
                        return MALELF_ERROR;
                }
                *machine = ehdr->eh64->e_machine;
                return MALELF_SUCCESS;
        } break;
        }
        return MALELF_ERROR;
}



static _i32 _malelf_ehdr_get_type(MalelfEhdr *ehdr, _u8 class, _u16 *type)
{
        assert(NULL != ehdr);
         
        switch(class) {
        case MALELF_ELF32:
                if (NULL == ehdr->eh32) {
                        return MALELF_ERROR;
                }
                *type = ehdr->eh32->e_type;
                return MALELF_SUCCESS;
                break;

        case MALELF_ELF64:
                if (NULL == ehdr->eh64) {
                        return MALELF_ERROR;
                }
                *type = ehdr->eh64->e_type;
                return MALELF_SUCCESS;
                break;
        }
        return MALELF_ERROR;
}

static _i32 _malelf_ehdr_get_version(MalelfEhdr *ehdr, _u8 class, _u8 *version)
{
        assert(NULL != ehdr);
         
        switch(class) {
        case MALELF_ELF32: {
                if (NULL == ehdr->eh32) {
                        return MALELF_ERROR;
                }
                *version = ehdr->eh32->e_version;
                return MALELF_SUCCESS;
        } break;

        case MALELF_ELF64: {
                if (NULL == ehdr->eh64) {
                        return MALELF_ERROR;
                }
                *version = ehdr->eh64->e_version;
                return MALELF_SUCCESS;
        } break;
        }
        return MALELF_ERROR;
}

_i32 malelf_ehdr_get_version(MalelfEhdr *ehdr, 
                             _u8 class, 
                             MalelfEhdrVersion *me_version)
{
        _u8 version;

        if (MALELF_SUCCESS != _malelf_ehdr_get_version(ehdr, class, &version)) {
                return MALELF_ERROR;
        }
        switch(version) {
        case EV_NONE: 
                *me_version = _me_version[0];
                break; 
        case EV_CURRENT: 
                *me_version = _me_version[1];
                break; 
        }
        return MALELF_SUCCESS;
}

_i32 malelf_ehdr_get_type (MalelfEhdr *ehdr, 
                           _u8 class, 
                           MalelfEhdrType *me_type)
{
        _u16 type;

        if (MALELF_SUCCESS != _malelf_ehdr_get_type(ehdr, class, &type)) {
                return MALELF_ERROR;
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
        }
        return MALELF_SUCCESS;
}



_i32 malelf_ehdr_get_machine(MalelfEhdr *ehdr, 
                             _u8 class, 
                             MalelfEhdrMachine *me_machine)
{

        _u8 machine;

        if (MALELF_SUCCESS != _malelf_ehdr_get_machine(ehdr, 
                                                       class, 
                                                       &machine)) {
                return MALELF_ERROR;
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
        }
        return MALELF_SUCCESS;
}





/*
_u8 malelf_ehdr_get_entry_point(MalelfEhdr *ehdr)
{
}


_u8 malelf_ehdr_get_phoff(MalelfEhdr *ehdr)
{
}

_u8 malelf_ehdr_get_shoff(MalelfEhdr *ehdr)
{
}

_i32 malelf_ehdr_get_flags(MalelfEhdr *ehdr)
{
}
*/

_i32 malelf_ehdr_get_ehsize(MalelfEhdr *ehdr, _u8 class, _u32 *size)
{
        switch(class) {
        case MALELF_ELF32: 
                if (NULL == ehdr->eh32) {
                        return MALELF_ERROR;
                }
                *size = ehdr->eh32->e_ehsize;
                return MALELF_SUCCESS;
             break;

        case MALELF_ELF64:
                if (NULL == ehdr->eh64) {
                        return MALELF_ERROR;
                }
                *size = ehdr->eh64->e_ehsize;
                return MALELF_SUCCESS;
             break;
        }
        return MALELF_ERROR;
}


_i32 malelf_ehdr_get_phentsize(MalelfEhdr *ehdr, _u8 class, _u32 *phentsize)
{
        switch(class) {
        case MALELF_ELF32: 
                if (NULL == ehdr->eh32) {
                        return MALELF_ERROR;
                }
                *phentsize = ehdr->eh32->e_phentsize;
                return MALELF_SUCCESS;
             break;

        case MALELF_ELF64:
                if (NULL == ehdr->eh64) {
                        return MALELF_ERROR;
                }
                *phentsize = ehdr->eh64->e_phentsize;
                return MALELF_SUCCESS;
             break;
        }
        return MALELF_ERROR;
}


_i32 malelf_ehdr_get_phnum(MalelfEhdr *ehdr, _u8 class, _u32 *phnum)
{
        switch(class) {
        case MALELF_ELF32: 
                if (NULL == ehdr->eh32) {
                        return MALELF_ERROR;
                }
                *phnum = ehdr->eh32->e_phnum;
                return MALELF_SUCCESS;
             break;

        case MALELF_ELF64:
                if (NULL == ehdr->eh64) {
                        return MALELF_ERROR;
                }
                *phnum = ehdr->eh64->e_phnum;
                return MALELF_SUCCESS;
             break;
        }
        return MALELF_ERROR;
}


_i32 malelf_ehdr_get_shentsize(MalelfEhdr *ehdr, _u8 class, _u32 *shentsize)
{
        switch(class) {
        case MALELF_ELF32: 
                if (NULL == ehdr->eh32) {
                        return MALELF_ERROR;
                }
                *shentsize = ehdr->eh32->e_shentsize;
                return MALELF_SUCCESS;
             break;

        case MALELF_ELF64:
                if (NULL == ehdr->eh64) {
                        return MALELF_ERROR;
                }
                *shentsize = ehdr->eh64->e_shentsize;
                return MALELF_SUCCESS;
             break;
        }
        return MALELF_ERROR;
}


_i32 malelf_ehdr_get_shnum(MalelfEhdr *ehdr, _u8 class, _u32 *shnum)
{
        switch(class) {
        case MALELF_ELF32: 
                if (NULL == ehdr->eh32) {
                        return MALELF_ERROR;
                }
                *shnum = ehdr->eh32->e_shnum;
                return MALELF_SUCCESS;
             break;

        case MALELF_ELF64:
                if (NULL == ehdr->eh64) {
                        return MALELF_ERROR;
                }
                *shnum = ehdr->eh64->e_shnum;
                return MALELF_SUCCESS;
             break;
        }
        return MALELF_ERROR;
}


_i32 malelf_ehdr_get_shstrndx(MalelfEhdr *ehdr, _u8 class, _u32 *shstrndx)
{
        switch(class) {
        case MALELF_ELF32: 
                if (NULL == ehdr->eh32) {
                        return MALELF_ERROR;
                }
                *shstrndx = ehdr->eh32->e_shstrndx;
                return MALELF_SUCCESS;
             break;

        case MALELF_ELF64:
                if (NULL == ehdr->eh64) {
                        return MALELF_ERROR;
                }
                *shstrndx = ehdr->eh64->e_shstrndx;
                return MALELF_SUCCESS;
             break;
        }
        return MALELF_ERROR;
}

_i32 malelf_ehdr_set(MalelfEhdr* ehdr, _u8 class, _u8 *mem, _u32 size) 
{
        assert(NULL != ehdr);
        assert(NULL != mem);

        switch (class) {
        case MALELF_ELF32:
                if (size > sizeof(Elf32_Ehdr)) {
                        return MALELF_EEHDR_OVERFLOW;
                }

                memcpy(ehdr->eh32, mem, size);
                break;
        case MALELF_ELF64:
                if (size > sizeof(Elf64_Ehdr)) {
                        return MALELF_EEHDR_OVERFLOW;
                }

                memcpy(ehdr->eh64, mem, size);
                break;
        default:
                return MALELF_EINVALID_CLASS;
        }

        return MALELF_SUCCESS;
}

