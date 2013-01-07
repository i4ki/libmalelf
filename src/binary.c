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
#include <malelf/binary.h>
#include <malelf/defines.h>

inline _u8 malelf_binary_is32(MalelfBinary *bin)
{
        assert(NULL != bin && NULL != bin->mem);
        return bin->mem[EI_CLASS] == MALELF_ELF32;
}

inline _u8 malelf_binary_is64(MalelfBinary *bin)
{
        assert(NULL != bin && NULL != bin->mem);
        return bin->mem[EI_CLASS] == MALELF_ELF64;
}

inline _i32 malelf_binary_get_arch(MalelfBinary *bin)
{
        assert(NULL != bin && NULL != bin->mem);
        
        if (MALELF_SUCCESS != malelf_binary_check_elf_magic(bin)) {
                return MALELF_ERROR;
        }

        bin->class = bin->mem[EI_CLASS];

        switch (bin->class) {
        case MALELF_ELF32: return MALELF_ELF32;
        case MALELF_ELF64: return MALELF_ELF64;
        default: return MALELF_ELFNONE;
        }
        
        return MALELF_ELFNONE;
}

_i32 malelf_binary_set_ehdr(MalelfEhdr *ehdr, MalelfBinary *bin)
{
        assert(MALELF_SUCCESS == malelf_binary_check_elf_magic(bin));

        bin->class = malelf_binary_get_arch(bin);

        switch (bin->class) {
        case MALELF_ELF32:
                ehdr->eh32 = (Elf32_Ehdr *) bin->mem;
                break;
        case MALELF_ELF64:
                ehdr->eh64 = (Elf64_Ehdr *) bin->mem;
                break;
        default:
                return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

MalelfEhdr *malelf_binary_get_ehdr(MalelfBinary *bin)
{
        assert(NULL != bin && NULL != bin->elf.ehdr);
	return bin->elf.ehdr;	
}

MalelfPhdr *malelf_binary_get_phdr(MalelfBinary *bin)
{
        assert(NULL != bin && NULL != bin->elf.phdr);
	return bin->elf.phdr;	
}

MalelfShdr *malelf_binary_get_shdr(MalelfBinary *bin)
{
        assert(NULL != bin && NULL != bin->elf.shdr);
        return bin->elf.shdr;
}

_i32 malelf_binary_set_phdr(MalelfPhdr *phdr, MalelfBinary *bin)
{
        MalelfEhdr *ehdr;

	ehdr = malelf_binary_get_ehdr(bin);
        
	assert(NULL != bin && NULL != ehdr);

	switch (bin->class) {
	case MALELF_ELFNONE: 
		return MALELF_ERROR; 
		break;
	case MALELF_ELF32: 
		phdr->ph32 = (Elf32_Phdr *) (bin->mem + ehdr->eh32->e_phoff);
		break;
	case MALELF_ELF64: 
		phdr->ph64 = (Elf64_Phdr *) (bin->mem + ehdr->eh64->e_phoff);
		break;
	}

	return MALELF_SUCCESS;
}

_i32 malelf_binary_set_shdr(MalelfShdr *shdr, MalelfBinary *bin)
{
        MalelfEhdr *ehdr;

	ehdr = malelf_binary_get_ehdr(bin);
        
	assert(NULL != bin && NULL != ehdr);

	switch (bin->class) {
	case MALELF_ELFNONE: 
		return MALELF_ERROR; 
		break;
	case MALELF_ELF32: 
		shdr->sh32 = (Elf32_Shdr *) (bin->mem + ehdr->eh32->e_shoff);
		break;
	case MALELF_ELF64: 
		shdr->sh64 = (Elf64_Shdr *) (bin->mem + ehdr->eh64->e_shoff);
		break;
	}

	return MALELF_SUCCESS;
}

_i32 malelf_binary_map(MalelfBinary *bin)
{
        _i32 error = MALELF_SUCCESS;
        
        assert(NULL != bin && NULL != bin->mem);

        error = malelf_binary_set_ehdr(bin->elf.ehdr, bin);
        
        if (MALELF_SUCCESS != error) {
                return error;
        }

        error = malelf_binary_set_phdr(bin->elf.phdr, bin);
        if (MALELF_SUCCESS != error ) {
                return MALELF_ERROR;
        }

        error = malelf_binary_set_shdr(bin->elf.shdr, bin);
        if (MALELF_SUCCESS != error) {
                return error;
        }

        assert(NULL != bin->elf.ehdr);
        assert(NULL != bin->elf.phdr);
        assert(NULL != bin->elf.shdr);

        return MALELF_SUCCESS;
}

inline _i32 malelf_binary_check_elf_magic(MalelfBinary *bin)
{
        _u8 valid = MALELF_SUCCESS;
        
	assert(NULL != bin && NULL != bin->mem);

        if (memcmp(bin->mem, ELFMAG, SELFMAG) == 0) {
                return MALELF_SUCCESS;
        } else {
                return MALELF_ENOT_ELF;
        }
    
        return valid;
}

_i32 malelf_binary_open(const char *fname, MalelfBinary *bin)
{
        return malelf_binary_open_generic(fname, bin, MALELF_ALLOC_MMAP);
}

_i32 malelf_binary_open_malloc(const char* fname, MalelfBinary *bin)
{
        return malelf_binary_open_generic(fname, bin, MALELF_ALLOC_MALLOC);
}

_i32 malelf_binary_open_generic(const char *fname,
                                MalelfBinary *bin,
                                _u8 alloc_type)
{
        struct stat st_info;
        
        assert(fname != NULL);
        assert(bin != NULL);

        bin->fd = open(fname, O_RDONLY);

        if (-1 == bin->fd) {
                return errno;
        }

        if (-1 == fstat(bin->fd, &st_info)) {
                return errno;
        }

        if (0 == st_info.st_size) {
                return MALELF_EEMPTY_FILE;
        }

        bin->size = st_info.st_size;

        if (MALELF_ALLOC_MMAP == alloc_type) {
                bin->mem = mmap(0,
                                st_info.st_size,
                                PROT_READ|PROT_WRITE,
                                MAP_PRIVATE,
                                bin->fd,
                                0);
                if (bin->mem == MAP_FAILED) {
                        return errno;
                }
                
                bin->alloc_type = MALELF_ALLOC_MMAP;
        } else if (MALELF_ALLOC_MALLOC == alloc_type) {
                _i16 n = 0;
                _u32 i = 0; 
                bin->mem = malloc(st_info.st_size * sizeof(_u8));
                if (NULL == bin->mem) {
                        return MALELF_EALLOC;
                }

                /* read the file byte by byte */
                while ((n = read(bin->fd, bin->mem + i, 1)) > 0 &&
                       i++);

                if (-1 == n) {
                        return errno;
                }
        } else {
                return MALELF_EALLOC;
        }

        if (MALELF_SUCCESS == malelf_binary_check_elf_magic(bin)) {
                malelf_binary_map(bin);
        }

        return MALELF_SUCCESS;
}

