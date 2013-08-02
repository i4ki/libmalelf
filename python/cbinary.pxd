# file: binary.pxd

from libc.stdint cimport uint8_t, uint32_t, uint64_t, int32_t

ctypedef void* MalelfShdr
ctypedef void* MalelfPhdr
ctypedef void* MalelfEhdr
ctypedef void* MalelfSegment
ctypedef void* MalelfSection

cdef extern from "/usr/include/elf.h":
    ctypedef struct Elf32_Phdr:
        pass


cdef extern from "malelf/binary.h":
    ctypedef struct MalelfBinary:
        char* fname
        char* bkpfile
        int32_t fd
        uint8_t* mem
        uint32_t size
        MalelfEhdr ehdr
        MalelfPhdr phdr
        MalelfShdr shdr
        uint8_t alloc_type
        uint32_t arch

    void malelf_binary_init(MalelfBinary *bin)
    void malelf_binary_close(MalelfBinary *bin)
    void malelf_binary_set_alloc_type(MalelfBinary *bin, uint8_t alloc_type)
    uint32_t malelf_binary_get_class(MalelfBinary *bin, uint8_t *arch)
    uint32_t malelf_binary_get_ehdr(MalelfBinary *bin, MalelfEhdr *ehdr)
    uint32_t malelf_binary_get_phdr(MalelfBinary *bin, MalelfPhdr *phdr)
    uint32_t malelf_binary_get_shdr(MalelfBinary *bin, MalelfShdr *shdr)
    uint32_t malelf_binary_get_alloc_type(MalelfBinary *bin, uint8_t *alloc_type)
    bint malelf_binary_open(MalelfBinary *bin, char *fname)
    bint malelf_binary_openw(MalelfBinary *bin, char *fname)
    int32_t malelf_binary_open_mmap(MalelfBinary *bin, char *fname)
    uint32_t malelf_binary_mmap_from(MalelfBinary *dest, MalelfBinary *src)
    uint32_t malelf_binary_malloc_from(MalelfBinary *dst, MalelfBinary *src)
    uint32_t malelf_binary_add_byte(MalelfBinary *bin, void *byte)
    uint32_t malelf_binary_copy_data(MalelfBinary *dst,
                                 MalelfBinary *src,
                                 uint32_t offset_start,
                                 uint32_t offset_end)
    int32_t malelf_binary_open_malloc(MalelfBinary *bin, char *fname)
    uint32_t malelf_binary_map(MalelfBinary *bin)
    uint32_t malelf_binary_check_elf_magic(MalelfBinary *bin)
    uint32_t malelf_binary_get_segment(MalelfBinary *bin,
                                   uint32_t idx,
                                   MalelfSegment *segment)
    uint32_t malelf_binary_get_section_name(MalelfBinary *bin,
                                        uint32_t idx,
                                        char **name)
    uint32_t malelf_binary_get_get_section(MalelfBinary *bin,
                                       uint32_t idx,
                                       MalelfSection *section)
    uint32_t malelf_binary_write_elf(MalelfBinary *bin,
                                 const char *fname)
    uint32_t malelf_binary_write(MalelfBinary *bin,
                             char *name,
                             uint8_t overwrite)
    uint32_t malelf_binary_create(MalelfBinary *output, uint8_t overwrite)
    uint32_t malelf_binary_create_elf_exec32(MalelfBinary *bin)
    uint32_t malelf_binary_create_elf_exec64(MalelfBinary *bin)
    uint32_t malelf_binary_create_elf_exec(MalelfBinary *bin, uint8_t arch)
    uint32_t malelf_binary_add_phdr32(MalelfBinary *bin, Elf32_Phdr *phdr)
