# file: cehdr.pxd

from libc.stdint cimport uint8_t, uint16_t, uint32_t, uint64_t, int32_t

cdef extern from "/usr/include/elf.h":
    ctypedef struct Elf32_Ehdr:
        pass
    
    ctypedef struct Elf64_Ehdr:
        pass


cdef extern from "malelf/ehdr.h":
    ctypedef union uhdr:
        Elf32_Ehdr *h32
        Elf64_Ehdr *h64

    ctypedef struct MalelfEhdr:
        uhdr _uhdr
        uint8_t arch

    ctypedef struct MalelfEhdrTable:
        uint16_t name
        int32_t value
        char *meaning

    int32_t malelf_ehdr_get_type(MalelfEhdr *ehdr, MalelfEhdrTable *me_type)
    int32_t malelf_ehdr_get_machine(MalelfEhdr *ehdr, MalelfEhdrTable *me_machine)
    int32_t malelf_ehdr_get_version(MalelfEhdr *ehdr, MalelfEhdrTable *version)
    int32_t malelf_ehdr_get_shoff(MalelfEhdr *ehdr, uint32_t *shoff)
    int32_t malelf_ehdr_get_phoff(MalelfEhdr *ehdr, uint32_t *pshoff)
    int32_t malelf_ehdr_get_entry(MalelfEhdr *ehdr, uint32_t *entry)
    int32_t malelf_ehdr_get_ehsize(MalelfEhdr *ehdr, uint32_t *ehsize)
    int32_t malelf_ehdr_get_phentsize(MalelfEhdr *ehdr, uint32_t *phentsize)
    int32_t malelf_ehdr_get_phnum(MalelfEhdr *ehdr, uint32_t *phnum)
    int32_t malelf_ehdr_get_shentsize(MalelfEhdr *ehdr, uint32_t *shentsize)
    int32_t malelf_ehdr_get_shnum(MalelfEhdr *ehdr, uint32_t *shnum)
    int32_t malelf_ehdr_get_shstrndx(MalelfEhdr *ehdr, uint32_t *shstrndx)
    int32_t malelf_ehdr_get_flags(MalelfEhdr *ehdr, uint32_t *flags)
    uint32_t malelf_ehdr_set_entry(MalelfEhdr *ehdr, uint32_t new_entry)
