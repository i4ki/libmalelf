# file: cshdr.pxd

from libc.stdint cimport uint8_t, uint16_t, uint32_t, uint64_t, int32_t

cdef extern from "/usr/include/elf.h":
    ctypedef struct Elf32_Shdr:
        pass
    
    ctypedef struct Elf64_Shdr:
        pass


cdef extern from "malelf/shdr.h":
    ctypedef union uhdr:
        Elf32_Shdr *h32
        Elf64_Shdr *h64

    ctypedef struct MalelfShdr:
        uhdr _uhdr
        uint8_t arch

    ctypedef struct MalelfSection:
       char *name
       uint16_t type
       uint32_t offset
       uint32_t size
       MalelfShdr *shdr

    ctypedef struct MalelfShdrType:
        uint16_t name
        int32_t value
        char *meaning

    uint32_t malelf_shdr_get_name(MalelfShdr *shdr, uint32_t *name, uint32_t index)
    uint32_t malelf_shdr_get_type(MalelfShdr *shdr, uint32_t *type, uint32_t index)
    uint32_t malelf_shdr_get_mstype(MalelfShdr *shdr, MalelfShdrType *ms_type, uint32_t index)
    uint32_t malelf_shdr_get_flags(MalelfShdr *shdr, uint32_t *flags, uint32_t index)
    uint32_t malelf_shdr_get_addr(MalelfShdr *shdr, uint32_t *addr, uint32_t index)
    uint32_t malelf_shdr_get_offset(MalelfShdr *shdr, uint32_t *offset, uint32_t index)
    uint32_t malelf_shdr_get_size(MalelfShdr *shdr, uint32_t *size, uint32_t index)
    uint32_t malelf_shdr_get_link(MalelfShdr *shdr, uint32_t *link, uint32_t index)
    uint32_t malelf_shdr_get_info(MalelfShdr *shdr, uint32_t *info, uint32_t index)
    uint32_t malelf_shdr_get_addralign(MalelfShdr *shdr, uint32_t *addralign, uint32_t index)
    uint32_t malelf_shdr_get_entsize(MalelfShdr *shdr, uint32_t *entsize, uint32_t index)

