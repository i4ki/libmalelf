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

#include "malelf/types.h"
#include "malelf/error.h"
#include "malelf/binary.h"

inline _i32 malelf_elf_arch(malelfBinary *bin)
{
        _u32 elfclass;

        assert(NULL != bin && NULL != bin->mem);
        
        if (MALELF_SUCCESS != malelf_check_elf_magic(bin)) {
                return MALELF_ERROR;
        }

        elfclass = bin->mem[EI_CLASS];

        if (ELFCLASS32 == elfclass) {
                return MALELF_ELF32;
        } else if (ELFCLASS64 == elfclass) {
                return MALELF_ELF64;
        }

        return MALELF_ELFNONE;
}

_i32 malelf_ehdr_set(malelfEhdr *ehdr, malelfBinary *bin)
{
        _u32 elfclass;
        if (MALELF_SUCCESS != malelf_check_elf_magic(bin)) {
                return MALELF_ERROR;
        }

        elfclass = malelf_elf_arch(bin);

        if (MALELF_ELFNONE == elfclass) {
                return MALELF_ERROR;
        }

        if (MALELF_ELF32 == elfclass) {
                ehdr->eh32 = (Elf32_Ehdr *) bin->mem;
        } else if (MALELF_ELF64 == elfclass) {
                ehdr->eh64 = (Elf64_Ehdr *) bin->mem;
        } else {
                return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_i32 _malelf_internal_map(malelfBinary *bin)
{
        assert(NULL != bin && NULL != bin->mem);

        if (MALELF_SUCCESS != malelf_ehdr_set(bin->elf.ehdr, bin)) {
                return MALELF_ERROR;
        }

        assert(NULL != bin->elf.ehdr);

        return MALELF_SUCCESS;
}

/**
 * Check if the binary contains the ELF magic numbers.
 *
 * @param binary malelfBinary previously opened by malelf_open*
 * @retval MALELF_SUCCESS If it is a valif ELF.
 * @retval MALELF_ENOT_ELF If is not ELF.
 */
inline _i32 malelf_check_elf_magic(malelfBinary *binary)
{
        _u8 valid = MALELF_SUCCESS;

        if (NULL == binary || NULL == binary->mem) {
                return MALELF_ERROR;
        }
  
        if (memcmp(binary->mem, ELFMAG, SELFMAG) == 0) {
                valid = MALELF_SUCCESS;
        } else {
                valid = MALELF_ENOT_ELF;
        }
    
        return valid;
}

/**
 * Opens an existing ELF binary and maps into malelfBinary with mmap(2).
 *
 * This function opens an ELF binary file, checks if it is a valid ELF and
 * maps your content in malelfBinary->mem with mmap(2).
 * If you want to copy the binary buffer inside a malloc'ed memory area, use
 * malelf_open_malloc().
 *
 * @param fname Filename
 * @param binary malelfBinary
 * @return MALELF_ERROR Error Status Code
 */
_i32 malelf_open(const char *fname, malelfBinary *binary)
{
        return malelf_open_generic(fname, binary, MALELF_ALLOC_MMAP);
}

/**
 * Opens an existing ELF binary and maps into malelfBinary with malloc(3).
 *
 * This function opens an ELF binary file, checks if it is a valid ELF and
 * maps your content in malelfBinary->mem with mmap(2).
 * If you want to maps the binary into memory with mmap(2) use malelf_open().
 *
 * @param fname Filename
 * @param binary malelfBinary
 * @return MALELF_ERROR Error Status Code
 */
_i32 malelf_open_malloc(const char* fname, malelfBinary *binary)
{
        return malelf_open_generic(fname, binary, MALELF_ALLOC_MALLOC);
}

_i32 malelf_open_generic(const char *fname,
                         malelfBinary *binary,
                         _u8 alloc_type)
{
        struct stat st_info;
        
        assert(fname != NULL);
        assert(binary != NULL);

        binary->fd = open(fname, O_RDONLY);

        if (-1 == binary->fd) {
                return errno;
        }

        if (-1 == fstat(binary->fd, &st_info)) {
                return errno;
        }

        if (st_info.st_size == 0) {
                return MALELF_EEMPTY_FILE;
        }

        binary->size = st_info.st_size;

        if (MALELF_ALLOC_MMAP == alloc_type) {
                binary->mem = mmap(0,
                                   st_info.st_size,
                                   PROT_READ|PROT_WRITE,
                                   MAP_PRIVATE,
                                   binary->fd,
                                   0);
                if (binary->mem == MAP_FAILED) {
                        return errno;
                }
                
                binary->alloc_type = MALELF_ALLOC_MMAP;
        } else if (MALELF_ALLOC_MALLOC == alloc_type) {
                _i16 n = 0;
                _u32 i = 0; 
                binary->mem = malelf_malloc(st_info.st_size * sizeof(_u8));
                if (NULL == binary->mem) {
                        return MALELF_EALLOC;
                }

                while ((n = read(binary->fd, binary->mem + i, 1)) > 0) {
                        i++;
                }

                if (-1 == n) {
                        return errno;
                }
        } else {
                return MALELF_EALLOC;
        }

        if (MALELF_SUCCESS == malelf_check_elf_magic(binary)) {
                _malelf_internal_map(binary);
        }

        return MALELF_SUCCESS;
}

