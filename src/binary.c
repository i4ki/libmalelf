
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
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>

#include <elf.h>

#include <malelf/types.h>
#include <malelf/error.h>
#include <malelf/binary.h>
#include <malelf/defines.h>

int ftruncate(int fd, off_t length);

_u32 malelf_binary_get_class(MalelfBinary *bin, _u8 *class)
{
        assert(NULL != bin && NULL != bin->mem);

        if (MALELF_SUCCESS != malelf_binary_check_elf_magic(bin)) {
                return MALELF_ERROR;
        }

        switch (bin->class) {
        case MALELF_ELF32:
                *class = MALELF_ELF32;
                break;
        case MALELF_ELF64:
                *class = MALELF_ELF64;
                break;
        default:
                *class = MALELF_ELFNONE;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_binary_get_ehdr(MalelfBinary *bin, MalelfEhdr *ehdr)
{
        assert(NULL != bin && NULL != ehdr);
        *ehdr = bin->ehdr;
        return MALELF_SUCCESS;
}

_u32 malelf_binary_get_phdr(MalelfBinary *bin, MalelfPhdr *phdr)
{
        assert(NULL != bin && NULL != phdr);
        *phdr = bin->phdr;
        return MALELF_SUCCESS;
}

_u32 malelf_binary_get_shdr(MalelfBinary *bin, MalelfShdr *shdr)
{
        assert(NULL != bin && NULL != shdr);
        *shdr = bin->shdr;
        return MALELF_SUCCESS;
}

static _i32 _malelf_binary_map_ehdr(MalelfBinary *bin)
{
        assert(MALELF_SUCCESS == malelf_binary_check_elf_magic(bin));

        switch (bin->class) {
        case MALELF_ELF32:
                bin->ehdr.uhdr.h32 = (Elf32_Ehdr *) bin->mem;
                break;
        case MALELF_ELF64:
                bin->ehdr.uhdr.h64 = (Elf64_Ehdr *) bin->mem;
                break;
        default:
                return MALELF_ERROR;
        }

        bin->ehdr.class = bin->class;
        return MALELF_SUCCESS;
}

static _i32 _malelf_binary_map_phdr(MalelfBinary *bin)
{
        MalelfEhdr ehdr;
        _u32 result;

	assert(NULL != bin);

	result = malelf_binary_get_ehdr(bin, &ehdr);
        if (MALELF_SUCCESS != result) {
                return MALELF_ERROR;
        }        

	switch (bin->class) {
	case MALELF_ELFNONE: 
		return MALELF_ERROR; 
		break;
	case MALELF_ELF32: 
		bin->phdr.uhdr.h32 = (Elf32_Phdr *) (bin->mem + ehdr.uhdr.h32->e_phoff);
		break;
	case MALELF_ELF64: 
		bin->phdr.uhdr.h64 = (Elf64_Phdr *) (bin->mem + ehdr.uhdr.h64->e_phoff);
		break;
	}
       
        bin->phdr.class = bin->class;
	return MALELF_SUCCESS;
}

static _i32 _malelf_binary_map_shdr(MalelfBinary *bin)
{
        MalelfEhdr ehdr;
        _u32 result;

	assert(NULL != bin);

	result = malelf_binary_get_ehdr(bin, &ehdr);
        if (MALELF_SUCCESS != result) {
                return MALELF_ERROR;
        }        

	switch (bin->class) {
	case MALELF_ELF32: 
		bin->shdr.uhdr.h32 = (Elf32_Shdr *) (bin->mem + ehdr.uhdr.h32->e_shoff);
		break;
	case MALELF_ELF64: 
		bin->shdr.uhdr.h64 = (Elf64_Shdr *) (bin->mem + ehdr.uhdr.h64->e_shoff);
		break;
	default: 
		return MALELF_ERROR;
	}

	return MALELF_SUCCESS;
}

_u32 malelf_binary_map(MalelfBinary *bin)
{
        _i32 error = MALELF_SUCCESS;
        
        assert(NULL != bin && NULL != bin->mem);

        bin->class = bin->mem[EI_CLASS]; 

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

_u32 malelf_binary_check_elf_magic(MalelfBinary *bin)
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

_u32 malelf_binary_get_alloc_type(MalelfBinary *bin, _u8 *alloc_type)
{
        assert(bin != NULL);
        *alloc_type = bin->alloc_type;
        return MALELF_SUCCESS;
}

void malelf_binary_init(MalelfBinary *bin)
{
        bin->fname = NULL;
        bin->fd = -1;
        bin->mem = NULL;
        bin->size = 0;
        bin->ehdr.uhdr.h32 = NULL;
        bin->phdr.uhdr.h32 = NULL;
        bin->shdr.uhdr.h32 = NULL;
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
        bin->ehdr.uhdr.h32 = NULL;
        bin->phdr.uhdr.h32 = NULL;
        bin->shdr.uhdr.h32 = NULL;
        bin->alloc_type = MALELF_ALLOC_NONE;
        bin->class = MALELF_ELFNONE;        
}

_i32 malelf_binary_close(MalelfBinary *bin)
{
        _u8 error = MALELF_SUCCESS;
        assert(bin != NULL);
        
	if (bin->fd != -1) {
		close(bin->fd);
	}
  
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

/**
 * Functions to get other informations of ELF
 */

static _u32 _malelf_binary_get_segment_32(_u32 segment_idx,
				   MalelfBinary *bin,
				   MalelfSegment *segment)
{
	MalelfPhdr stphdr;
	Elf32_Phdr *phdr32;
	int error = MALELF_SUCCESS;

	assert(bin != NULL && bin->mem != NULL);
	
	error = malelf_binary_get_phdr(bin, &stphdr);
	if (error != MALELF_SUCCESS) {
		return error;
	}

	phdr32 = stphdr.uhdr.h32;

	phdr32 += segment_idx;

	segment->class = bin->class;
	segment->index = segment_idx;
	segment->size = phdr32->p_filesz;
	segment->mem = bin->mem + phdr32->p_offset;
	segment->phdr = &stphdr;

	return MALELF_SUCCESS;
}

static _u32 _malelf_binary_get_segment_64(_u32 segment_idx,
				  MalelfBinary *bin,
				  MalelfSegment *segment) 
{
	MalelfPhdr stphdr;
	Elf64_Phdr *phdr64;
	int error = MALELF_SUCCESS;

	assert(bin != NULL && bin->mem != NULL);
	
	error = malelf_binary_get_phdr(bin, &stphdr);
	if (error != MALELF_SUCCESS) {
		return error;
	}

	phdr64 = stphdr.uhdr.h64;

	phdr64 += segment_idx;

	segment->class = bin->class;
	segment->index = segment_idx;
	segment->size = phdr64->p_filesz;
	segment->mem = bin->mem + phdr64->p_offset;
	segment->phdr = &stphdr;

	return MALELF_SUCCESS;
}

_u32 malelf_binary_get_segment(_u32 segment_idx, 
			       MalelfBinary *bin, 
			       MalelfSegment *segment)
{
	int error = MALELF_SUCCESS;

	assert(NULL != bin);
	assert(NULL != bin->mem);

	switch (bin->class) {
	case MALELF_ELF32:
		error = _malelf_binary_get_segment_32(segment_idx, 
						      bin, 
						      segment);
		
		break;
	case MALELF_ELF64:
		error = _malelf_binary_get_segment_64(segment_idx,
						      bin,
						      segment);
		break;
	default:
		error = MALELF_EINVALID_CLASS;
	}

	return error;
}

inline char* _malelf_binary_get_section_name(_u32 section_idx, 
					     MalelfBinary *bin)
{
	int error = MALELF_SUCCESS;
	MalelfShdr ushdr;
	Elf32_Shdr *shdr32;
	Elf64_Shdr *shdr64;

	error = malelf_binary_get_shdr(bin, &ushdr);

	if (error != MALELF_SUCCESS) {
		return NULL;
	}

	switch (bin->class) {
	case MALELF_ELF32: {
		shdr32 = ushdr.uhdr.h32;
		shdr32 += section_idx;
		
		return (char *)(bin->mem + 
			bin->shdr.uhdr.h32[bin->ehdr.uhdr.h32->e_shstrndx].sh_offset + 
			shdr32->sh_name);
	}
	case MALELF_ELF64: {
		shdr64 = ushdr.uhdr.h64;
		shdr64 += section_idx;

		return (char *)(bin->mem + 
			bin->shdr.uhdr.h64[bin->ehdr.uhdr.h64->e_shstrndx].sh_offset + 
			shdr64->sh_name);
	}
	default:
		return NULL;
	}

	return NULL;	
}

_u32 malelf_binary_get_section_name(_u32 section_idx, 
				    MalelfBinary *bin,
				    char **name)
{
	char *n = _malelf_binary_get_section_name(section_idx, bin);
	*name = n;
	return (*name == NULL) ? MALELF_ERROR : MALELF_SUCCESS;
}

static _u32 _malelf_binary_get_section32(_u32 section_idx,
					 MalelfBinary *bin,
					 MalelfSection *section)
{
	int error = MALELF_SUCCESS;
	Elf32_Shdr *shdr32;

	MalelfShdr ushdr;

	error = malelf_binary_get_shdr(bin, &ushdr);

	if (error != MALELF_SUCCESS) {
		return error;
	}

	shdr32 = ushdr.uhdr.h32;
	shdr32 += section_idx;

	section->name = _malelf_binary_get_section_name(section_idx, bin);
	section->offset = shdr32->sh_offset;
	section->size = shdr32->sh_size;
	section->shdr = &ushdr;
	
	return MALELF_SUCCESS;
}

static _u32 _malelf_binary_get_section64(_u32 section_idx,
					 MalelfBinary *bin,
					 MalelfSection *section)
{
	int error = MALELF_SUCCESS;
	Elf64_Shdr *shdr64;
	MalelfShdr ushdr;

	error = malelf_binary_get_shdr(bin, &ushdr);

	if (error != MALELF_SUCCESS) {
		return error;
	}

	shdr64 = ushdr.uhdr.h64;
	shdr64 += section_idx;

	section->name = _malelf_binary_get_section_name(section_idx, bin);
	section->offset = shdr64->sh_offset;
	section->size = shdr64->sh_size;
	
	return MALELF_SUCCESS;
}

_u32 malelf_binary_get_section(_u32 section_idx, 
			       MalelfBinary *bin, 
			       MalelfSection *section)
{
	int error = MALELF_SUCCESS;

	assert(NULL != bin && NULL != bin->mem);

	switch (bin->class) {
	case MALELF_ELF32:
		error = _malelf_binary_get_section32(section_idx, bin, section);
		break;
	case MALELF_ELF64:
		error = _malelf_binary_get_section64(section_idx, bin, section);
		break;
	default:
		error = MALELF_EINVALID_CLASS;
	}

	return error;
}

static _u32 _malelf_binary_get_section_by_name32(const char *name,
						 MalelfBinary *bin,
						 MalelfSection *section)
{
	int error = MALELF_SUCCESS;
	MalelfShdr ushdr;
	MalelfEhdr stehdr;
	Elf32_Shdr *sections;
	Elf32_Ehdr *ehdr;
	_u32 i = 0;

	error = malelf_binary_get_shdr(bin, &ushdr);
	if (error != MALELF_SUCCESS) {
		return error;
	}

	sections = ushdr.uhdr.h32;

	error = malelf_binary_get_ehdr(bin, &stehdr);
	if (error != MALELF_SUCCESS) {
		return error;
	}

	ehdr = stehdr.uhdr.h32;

	/* if the section is not found returns error */
	error = MALELF_ERROR;

	for (i = 0; i < ehdr->e_shnum; i++) {
		Elf32_Shdr *s = &sections[i];
		if (s->sh_type == SHT_NULL)
			continue;

		char *section_name = _malelf_binary_get_section_name(i, bin);
		if (section_name != NULL && !strcmp(name, section_name)) {
			return _malelf_binary_get_section32(i, bin, section);
			
		}
	}
	
	return error;
}

_u32 _malelf_binary_get_section_by_name64(const char *name, 
					MalelfBinary *bin,
					MalelfSection *section)
{
	int error = MALELF_SUCCESS;
	MalelfShdr ushdr;
	MalelfEhdr stehdr;
	Elf64_Shdr *sections;
	Elf64_Ehdr *ehdr;
	_u32 i = 0;

	error = malelf_binary_get_shdr(bin, &ushdr);
	if (error != MALELF_SUCCESS) {
		return error;
	}

	sections = ushdr.uhdr.h64;

	error = malelf_binary_get_ehdr(bin, &stehdr);
	if (error != MALELF_SUCCESS) {
		return error;
	}

	ehdr = stehdr.uhdr.h64;

	/* if the section is not found returns error */
	error = MALELF_ERROR;

	for (i = 0; i < ehdr->e_shnum; i++) {
		Elf64_Shdr *s = &sections[i];
		if (s->sh_type == SHT_NULL)
			continue;

		char *section_name = _malelf_binary_get_section_name(i, bin);
		if (section_name != NULL && !strcmp(name, section_name)) {
			return _malelf_binary_get_section64(i, bin, section);
			
		}
	}
	
	return error;	
}

_u32 malelf_binary_get_section_by_name(const char *name, 
				       MalelfBinary *bin,
				       MalelfSection *section)
{
	int error = MALELF_SUCCESS;
	assert(NULL != name && NULL != bin && NULL != bin->mem);


	switch (bin->class) {
	case MALELF_ELF32:
		error = _malelf_binary_get_section_by_name32(name, 
							   bin,
							   section);
		break;
	case MALELF_ELF64:
		error = _malelf_binary_get_section_by_name64(name,
							     bin,
							     section);
		break;
	default:
		error = MALELF_EINVALID_CLASS;
	}

	return error;
}

_u32 malelf_binary_write32(MalelfBinary *bin, const char *fname)
{
	int error = MALELF_SUCCESS;
	MalelfEhdr stehdr;
	MalelfPhdr stphdr;
	MalelfShdr stshdr;
	Elf32_Ehdr *ehdr;
	Elf32_Phdr *phdr;
	Elf32_Shdr *shdr;
	int i;

	struct stat st_info;
	char *bkpfile;

	assert(NULL != bin);

	if (NULL != fname) {
		bin->fname = (char *)fname;
	}

	close(bin->fd);

	if (0 == stat(bin->fname, &st_info)) {
		/* file exists, backuping... */
		bkpfile = tmpnam(NULL);
		error = rename(bin->fname, bkpfile);
		if (!error) {
			return errno;
		}

		bin->bkpfile = bkpfile;
	}

	bin->fd = open(bin->fname, O_RDWR|O_CREAT|O_TRUNC, 0755);
	if (bin->fd == -1) {
		return errno;
	}

	error = malelf_binary_get_ehdr(bin, &stehdr);
	if (MALELF_SUCCESS != error) {
		return error;
	}

	error = malelf_binary_get_phdr(bin, &stphdr);
	if (MALELF_SUCCESS != error) {
		return error;
	}

	error = malelf_binary_get_shdr(bin, &stshdr);

	if (MALELF_SUCCESS != error) {
		return error;
	}

	/* PHDR and SHDR are'nt always required.
	   Executable file doesn't need a SHT ...
	   Relocatable file doesn't need a PHT ...

	   This function allows the write of partial MalelfBinary objects
	   created by malelf_binary_create_elf_* functions.
	   
	   assert(NULL != stphdr.uhdr.h32);
	   assert(NULL != stshdr.uhdr.h32);
	*/

	ehdr = (Elf32_Ehdr *) stehdr.uhdr.h32;
	phdr = (Elf32_Phdr *) stphdr.uhdr.h32;
	shdr = (Elf32_Shdr *) stshdr.uhdr.h32;

	/* required to minimal ELF */
	assert(NULL != ehdr);

	/* Some binaries does'nt have the Section Header Table.
	   Binaries written in assembly could'nt have a SHT.
	   The section header table can be ommited for size performance. 
	   Only PHT is required to ET_EXEC binaries.
	   
	   assert(NULL != phdr);
	   assert(NULL != shdr); 
        */

        /* We're expecting that bin->size have the correct size of the
           binary to write. If not, this approuch will not work ...
           Here, we truncate the binary to the specified length and then
           we seek to the position to write the data. */           
	error = ftruncate(bin->fd, bin->size);

	lseek(bin->fd, 0, SEEK_SET);

	/* Writing EHDR */
	error = malelf_write(bin->fd, bin->mem, sizeof (Elf32_Ehdr));

	if (MALELF_SUCCESS != error) {
		return error;
	}

	lseek(bin->fd, ehdr->e_phoff, SEEK_SET);
	
	/* Writing PHDR's */
	for (i = 0; i < ehdr->e_phnum; i++) {
		Elf32_Phdr *p = phdr + i;
		error = malelf_write(bin->fd, (_u8*) p, sizeof (Elf32_Phdr));

		if (MALELF_SUCCESS != error) {
			return error;
		}
	}

        /* Testing if the binary have SHT */
	if (ehdr->e_shnum != 0 && 
	    ehdr->e_shoff > (ehdr->e_phoff + 
			     (sizeof(Elf32_Phdr) * ehdr->e_phnum)) &&
	    ehdr->e_shoff < bin->size) {
		/* Writing sections */
		for (i = 0; i < ehdr->e_shnum; i++) {
			Elf32_Shdr *s = shdr + i;
			if (s->sh_type == SHT_NULL || s->sh_size == 0) {
				/* skipping SHT_NULL */
				continue;
			}

			lseek(bin->fd, s->sh_offset, SEEK_SET);

			error = malelf_write(bin->fd, 
					     bin->mem + s->sh_offset, 
					     s->sh_size);
			if (MALELF_SUCCESS != error) {
				return error;
			}		
		}

		lseek(bin->fd, ehdr->e_shoff, SEEK_SET);

		/* Writing SHT */
		for (i = 0; i < ehdr->e_shnum; i++) {
			Elf32_Shdr *s = shdr + i;
			error = malelf_write(bin->fd, 
					     (_u8 *) s, 
					     sizeof(Elf32_Shdr));
			if (MALELF_SUCCESS != error) {
				return error;
			}
		}
	} else {
		
		/* writing binary content using the program headers */
		for (i = 0; i < ehdr->e_phnum; i++) {
			Elf32_Phdr *p = phdr + i;
			if (p->p_type == PT_NULL)
				continue;

			lseek(bin->fd, p->p_offset, SEEK_SET);
			error = malelf_write(bin->fd,
					     bin->mem + p->p_offset,
					     p->p_filesz);

			if (MALELF_SUCCESS != error) {
				return error;
			}
		}
	}

	return error;
}

_u32 malelf_binary_write(MalelfBinary *bin, const char *fname)
{
	_u32 error = MALELF_SUCCESS;

	switch (bin->class) {
	case MALELF_ELF32:
		error = malelf_binary_write32(bin, fname);
		break;
	case MALELF_ELF64:
		error = malelf_binary_write32(bin, fname);
		break;
	default:
		error = MALELF_EINVALID_CLASS;
	}

	return error;	
}

_u32 malelf_binary_create_elf_exec32(MalelfBinary *bin) 
{
	_u32 error = MALELF_SUCCESS;
	Elf32_Ehdr *ehdr;

	bin->mem = malelf_malloc(sizeof (Elf32_Ehdr));
	if (!bin->mem) {
		return MALELF_EALLOC;
	}

	bin->alloc_type = MALELF_ALLOC_MALLOC;
	bin->size = sizeof (Elf32_Ehdr);
	bin->class = MALELF_ELF32;

	ehdr = (Elf32_Ehdr *) bin->mem;
	ehdr->e_ident[0] = ELFMAG0;
	ehdr->e_ident[1] = ELFMAG1;
	ehdr->e_ident[2] = ELFMAG2;
	ehdr->e_ident[3] = ELFMAG3;
	ehdr->e_ident[4] = ELFCLASS32;
	ehdr->e_ident[5] = ELFDATA2LSB;
	ehdr->e_ident[6] = EV_CURRENT;
	ehdr->e_ident[7] = ELFOSABI_LINUX;
	ehdr->e_ident[8] = 0;
	ehdr->e_ident[9] = 0;
	ehdr->e_ident[10] = 0;
	ehdr->e_ident[11] = 0;
	ehdr->e_ident[12] = 0;
	ehdr->e_ident[13] = 0;
	ehdr->e_ident[14] = 0;
	ehdr->e_ident[15] = 0;

	/* executable file */
	ehdr->e_type = ET_EXEC;
	ehdr->e_machine = EM_386;
	ehdr->e_version = EV_CURRENT;
	ehdr->e_entry = 0x00;
	ehdr->e_phoff = 0x00;
	ehdr->e_shoff = 0x00;
	ehdr->e_flags = 0x00;
	ehdr->e_ehsize = sizeof (Elf32_Ehdr); // 52 bytes
	ehdr->e_phentsize = 0x00;
	ehdr->e_phnum = 0x00;
	ehdr->e_shentsize = 0x00;
	ehdr->e_shnum = 0x00;
	ehdr->e_shstrndx = SHN_UNDEF;

	_malelf_binary_map_ehdr(bin);

	return error;
}

_u32 malelf_binary_add_phdr32(MalelfBinary *bin, Elf32_Phdr *new_phdr)
{
	Elf32_Ehdr *ehdr;

	assert(NULL != bin->mem);
	assert(NULL != bin->ehdr.uhdr.h32);
	assert(NULL != new_phdr);

	ehdr = bin->ehdr.uhdr.h32;
	
	if (ehdr->e_phoff == 0 && ehdr->e_phnum == 0) {
		Elf32_Phdr phdr;
		_u32 old_size = bin->size;
		/* doesn't have PHT */

		/* allocate space for two program headers, 
		   the first is PT_NULL */
		printf("OLD size = %u, NEW size = %u\n",
		       bin->size,
		       bin->size + 
		       sizeof(Elf32_Phdr) * 2);
		bin->mem = malelf_realloc(bin->mem, 
					  bin->size + 
					  sizeof(Elf32_Phdr) * 2);
		if (bin->mem == NULL) {
			return MALELF_EALLOC;
		}
		
		phdr.p_type = PT_NULL;
		phdr.p_offset = 0x00;
		phdr.p_vaddr = 0x00;
		phdr.p_paddr = 0x00;
		phdr.p_filesz = 0x00;
		phdr.p_memsz = 0x00;
		phdr.p_flags = 0x00;
		phdr.p_align = 0x00;

		memcpy(bin->mem + old_size, &phdr, sizeof (Elf32_Phdr));

		ehdr->e_phoff = sizeof (Elf32_Ehdr);
		ehdr->e_phnum = 1;
		ehdr->e_phentsize = sizeof(Elf32_Phdr);
		bin->size += 2 * sizeof (Elf32_Phdr);

		_malelf_binary_map_phdr(bin);
	} else {
		bin->mem = malelf_realloc(bin->mem, 
					  bin->size +
					  sizeof(Elf32_Phdr));

		if (!bin->mem) {
			return MALELF_EALLOC;
		}

		bin->size += sizeof(Elf32_Phdr);
	}

	printf("bin->size = %u and size = %u\n", bin->size,
	       ehdr->e_phoff + 
	       (sizeof (Elf32_Phdr) * ehdr->e_phnum));

	memcpy(bin->mem + ehdr->e_phoff + 
	       (sizeof (Elf32_Phdr) * ehdr->e_phnum),
	       new_phdr, sizeof (Elf32_Phdr));

	ehdr->e_phnum++;
				 
	return MALELF_SUCCESS;
}
