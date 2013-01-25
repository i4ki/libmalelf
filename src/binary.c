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
#include <malelf/binary.h>
#include <malelf/defines.h>

inline _i32 malelf_binary_get_class(MalelfBinary *bin)
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

MalelfEhdr malelf_binary_get_ehdr(MalelfBinary *bin)
{
        assert(NULL != bin);
	return bin->elf.ehdr;	
}

MalelfPhdr malelf_binary_get_phdr(MalelfBinary *bin)
{
        assert(NULL != bin);
	return bin->elf.phdr;	
}

MalelfShdr malelf_binary_get_shdr(MalelfBinary *bin)
{
        assert(NULL != bin);
        return bin->elf.shdr;
}

static _i32 _malelf_binary_map_ehdr(MalelfBinary *bin)
{
        assert(MALELF_SUCCESS == malelf_binary_check_elf_magic(bin));

        bin->class = malelf_binary_get_class(bin);

        switch (bin->class) {
        case MALELF_ELF32:
                bin->elf.ehdr.h32 = (Elf32_Ehdr *) bin->mem;
                break;
        case MALELF_ELF64:
                bin->elf.ehdr.h64 = (Elf64_Ehdr *) bin->mem;
                break;
        default:
                return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

static _i32 _malelf_binary_map_phdr(MalelfBinary *bin)
{
        MalelfEhdr ehdr;

	ehdr = malelf_binary_get_ehdr(bin);
        
	assert(NULL != bin);

	switch (bin->class) {
	case MALELF_ELFNONE: 
		return MALELF_ERROR; 
		break;
	case MALELF_ELF32: 
		bin->elf.phdr.h32 = (Elf32_Phdr *) (bin->mem + ehdr.h32->e_phoff);
		break;
	case MALELF_ELF64: 
		bin->elf.phdr.h64 = (Elf64_Phdr *) (bin->mem + ehdr.h64->e_phoff);
		break;
	}

	return MALELF_SUCCESS;
}

static _i32 _malelf_binary_map_shdr(MalelfBinary *bin)
{
        MalelfEhdr ehdr;

	ehdr = malelf_binary_get_ehdr(bin);
        
	assert(NULL != bin);

	switch (bin->class) {
	case MALELF_ELFNONE: 
		return MALELF_ERROR; 
		break;
	case MALELF_ELF32: 
		bin->elf.shdr.h32 = (Elf32_Shdr *) (bin->mem + ehdr.h32->e_shoff);
		break;
	case MALELF_ELF64: 
		bin->elf.shdr.h64 = (Elf64_Shdr *) (bin->mem + ehdr.h64->e_shoff);
		break;
	}

	return MALELF_SUCCESS;
}

_i32 malelf_binary_map(MalelfBinary *bin)
{
        _i32 error = MALELF_SUCCESS;
        
        assert(NULL != bin && NULL != bin->mem);

        error = _malelf_binary_map_ehdr(bin);
        if (MALELF_SUCCESS != error) {
                return error;
        }

        error = _malelf_binary_map_phdr(bin);
        if (MALELF_SUCCESS != error ) {
                return error;
        }

        error = _malelf_binary_map_shdr(bin);
        if (MALELF_SUCCESS != error) {
                return error;
        }

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

_u8 malelf_binary_get_alloc_type(MalelfBinary *bin)
{
        assert(bin != NULL);
        return bin->alloc_type;
}

void malelf_binary_init(MalelfBinary *bin)
{
        bin->fname = NULL;
        bin->fd = -1;
        bin->mem = NULL;
        bin->size = 0;
        bin->elf.ehdr.h32 = NULL;
        bin->elf.phdr.h32 = NULL;
        bin->elf.shdr.h32 = NULL;
        bin->alloc_type = MALELF_ALLOC_MMAP;
        bin->class = MALELF_ELFNONE;
}

void malelf_binary_set_alloc_type(MalelfBinary *bin, _u8 alloc_type)
{
        assert(bin != NULL);
        if ((MALELF_ALLOC_MMAP == alloc_type) ||
            (MALELF_ALLOC_MALLOC == alloc_type)) {
                bin->alloc_type = alloc_type;
        }
}

_i32 malelf_binary_open_mmap(char *fname, MalelfBinary *bin)
{
        malelf_binary_set_alloc_type(bin, MALELF_ALLOC_MMAP);
        return malelf_binary_open(fname, bin);
}

_i32 malelf_binary_open_malloc(char* fname, MalelfBinary *bin)
{
        malelf_binary_set_alloc_type(bin, MALELF_ALLOC_MALLOC);
        return malelf_binary_open(fname, bin);
}

static _i32 _malelf_binary_verify_file(char*fname, MalelfBinary *bin)
{
        struct stat st_info;

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
        return MALELF_SUCCESS;
}

static _i32 _malelf_binary_mmap_load(MalelfBinary *bin)
{

        bin->mem = mmap(0,
                        bin->size,
                        PROT_READ|PROT_WRITE,
                        MAP_PRIVATE,
                        bin->fd,
                        0);
       if (MAP_FAILED == bin->mem) {
               return errno;
       }

       return MALELF_SUCCESS;
}

static _i32 _malelf_binary_malloc_load(MalelfBinary *bin)
{
        _i16 n = 0;
        _u32 i = 0; 
        bin->mem = malloc(bin->size * sizeof(_u8));
        if (NULL == bin->mem) {
                return MALELF_EALLOC;
        }

        /* read the file byte by byte */
        while ((n = read(bin->fd, bin->mem + i, 1)) > 0 && ++i);

        if (-1 == n) {
                return errno;
        }
        return MALELF_SUCCESS;
}

_i32 malelf_binary_open(char *fname, MalelfBinary *bin)
{
        assert(fname != NULL);
        assert(bin != NULL);
       
        _i32 result = _malelf_binary_verify_file(fname, bin);        
        if (MALELF_SUCCESS != result) {
                return result;
        }

        bin->fname = fname;

        if (MALELF_ALLOC_MMAP == bin->alloc_type) {
                result = _malelf_binary_mmap_load(bin);
                if (MALELF_SUCCESS != result) {
                        return result;
                }
        } else if (MALELF_ALLOC_MALLOC == bin->alloc_type) {
                result = _malelf_binary_malloc_load(bin);
                if (MALELF_SUCCESS != result) {
                        return result;
                }
        } else {
                return MALELF_EALLOC;
        }

        result = malelf_binary_check_elf_magic(bin);
        if (MALELF_SUCCESS != result) {
                return result;      
        }

        result = malelf_binary_map(bin);
        if (MALELF_SUCCESS != result) {
                return result;
        }

        return result;
}

static void _malelf_binary_cleanup(MalelfBinary *bin)
{
        assert(bin != NULL);

        bin->fname = NULL;
        bin->fd = -1;
        bin->mem = NULL;
        bin->size = 0;
        bin->elf.ehdr.h32 = NULL;
        bin->elf.phdr.h32 = NULL;
        bin->elf.shdr.h32 = NULL;
        bin->alloc_type = MALELF_ALLOC_NONE;
        bin->class = MALELF_ELFNONE;        
}

_i32 malelf_binary_close(MalelfBinary *bin)
{
        _u8 error = MALELF_SUCCESS;
        assert(bin != NULL);
        
        close(bin->fd);
  
        if (MALELF_ALLOC_MALLOC == bin->alloc_type) {
                if (NULL != bin->mem) {
                        free(bin->mem);
                }
        } else if (MALELF_ALLOC_MMAP == bin->alloc_type) {
                if (-1 == munmap(bin->mem, bin->size)) {
                        error = errno;
                }
        }

        _malelf_binary_cleanup(bin);
        
        return error;
}
