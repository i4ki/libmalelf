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
 * Contributorss:
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
#include <malelf/debug.h>
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
                bin->phdr.uhdr.h32 = (Elf32_Phdr *)
                  (bin->mem + ehdr.uhdr.h32->e_phoff);
                break;
        case MALELF_ELF64:
                bin->phdr.uhdr.h64 = (Elf64_Phdr *)
                  (bin->mem + ehdr.uhdr.h64->e_phoff);
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
                bin->shdr.uhdr.h32 = (Elf32_Shdr *)
                  (bin->mem + ehdr.uhdr.h32->e_shoff);
                break;
        case MALELF_ELF64:
                bin->shdr.uhdr.h64 = (Elf64_Shdr *)
                  (bin->mem + ehdr.uhdr.h64->e_shoff);
                break;
        default:
                return MALELF_ERROR;
        }

        bin->shdr.class = bin->class;

        return MALELF_SUCCESS;
}

_u32 malelf_binary_map(MalelfBinary *bin)
{
        _i32 error = MALELF_SUCCESS;
        _u32 class = 0;

        assert(NULL != bin && NULL != bin->mem);

        if (bin->size < EI_CLASS) {
                return MALELF_EINVALID_CLASS;
        }

        class = bin->mem[EI_CLASS];

        if (class < MALELF_FLAT && class > MALELF_ELFNONE) {
                if (bin->class >= MALELF_FLAT) {
                        MALELF_DEBUG_WARN("Binary previously configured"
                                          " as FLAT binary, but for now"
                                          " was detected as ELF. "
                                          "Changing bin->class to ELF.");
                }

                bin->class = class;
        } else {
                MALELF_DEBUG_WARN("This memory content isn't ELF and "
                                  "cannot be mapped in ELF structures. "
                                  "Skipping...");
                return MALELF_EINVALID_CLASS;
        }

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

        malelf_debug_init();
        MALELF_DEBUG_INFO("MalelfBinary structure initialized.");
}

void malelf_binary_init_all(_u32 count, ...)
{
        va_list arg;
        va_start(arg, count);
        _u32 i = 0;

        MalelfBinary *bptr = NULL;
        for (i = 0; i < count; i++) {
                bptr = va_arg(arg, MalelfBinary *);
                if (bptr != NULL) {
                        malelf_binary_init(bptr);
                }
        }

        va_end(arg);
}


void malelf_binary_set_alloc_type(MalelfBinary *bin, _u8 alloc_type)
{
        assert(bin != NULL);
        if ((MALELF_ALLOC_MMAP == alloc_type) ||
            (MALELF_ALLOC_MALLOC == alloc_type)) {
                bin->alloc_type = alloc_type;
        }
}

_i32 malelf_binary_open_mmap(MalelfBinary *bin, char *fname)
{
        malelf_binary_set_alloc_type(bin, MALELF_ALLOC_MMAP);
        return malelf_binary_open(bin, fname);
}

_i32 malelf_binary_open_malloc(MalelfBinary *bin, char *fname)
{
        malelf_binary_set_alloc_type(bin, MALELF_ALLOC_MALLOC);
        return malelf_binary_open(bin, fname);
}

static _i32 _malelf_binary_open(MalelfBinary *bin,
                                char *fname,
                                int flags)
{
        _u8 is_creat = (flags & O_CREAT) == O_CREAT;
        _u32 error;
        struct stat st_info;

        if (!is_creat) {
                bin->fd = open(fname, flags);
        } else {
                bin->fd = open(fname, flags, 0666);
        }

        if (-1 == bin->fd) {
                error = errno;
                MALELF_DEBUG_ERROR("Failed to open file '%s'.",
                                   fname);
                return error;
        }

        if (-1 == fstat(bin->fd, &st_info)) {
                error = errno;
                MALELF_DEBUG_ERROR("Failed to stat file '%s'.",
                                   bin->fname);
                return error;
        }

        if (0 == st_info.st_size && !is_creat) {
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
               int error = errno;
               MALELF_DEBUG("Failed to load '%u' bytes of binary '%s' "
                            "with mmap(2)", bin->size, bin->fname);
               return error;
       }

       MALELF_DEBUG("Binary '%s' loaded by mmap(2)", bin->fname);
       return MALELF_SUCCESS;
}

_u32 malelf_binary_malloc_from(MalelfBinary *dest,
                               MalelfBinary *src)
{
        _u32 error;

        if (src->mem == NULL || src->size == 0) {
                return MALELF_ERROR;
        }

        if (dest->mem != NULL) {
                if (dest->alloc_type == MALELF_ALLOC_MALLOC) {
                        free(dest->mem);
                } else if (dest->alloc_type == MALELF_ALLOC_MMAP) {
                        if ((munmap(dest->mem, dest->size)) == -1) {
                                return errno;
                        }
                } else {
                        dest->mem = NULL;
                }
        }

        dest->mem = malloc(src->size);
        dest->alloc_type = MALELF_ALLOC_MALLOC;
        dest->size = src->size;
        dest->class = src->class;
        memcpy(dest->mem, src->mem, dest->size);

        if (dest->class > MALELF_ELF && dest->class < MALELF_FLAT) {
                error = malelf_binary_map(dest);
                if (MALELF_SUCCESS != error) {
                        return error;
                }
        }

        return MALELF_SUCCESS;
}

_u32 malelf_binary_mmap_from(MalelfBinary *dest,
                             MalelfBinary *src)
{
        dest->mem = mmap(0,
                   src->size,
                   PROT_READ,
                   MAP_SHARED,
                   src->fd,
                   0);

        if (dest->mem == MAP_FAILED) {
                MALELF_DEBUG_ERROR("Failed to map binary in memory...");
                return MALELF_EALLOC;
        }

        dest->size = src->size;

        return MALELF_SUCCESS;
}

_u32 malelf_binary_add_byte(MalelfBinary *bin,
                                   void *byte)
{
        if (bin->alloc_type != MALELF_ALLOC_MALLOC) {
                return MALELF_ERROR;
        }

        bin->size++;

        bin->mem = malelf_realloc(bin->mem, bin->size);
        if (NULL == bin->mem) {
                return MALELF_EALLOC;
        }

        memcpy(bin->mem + (bin->size - 1), byte, 1);
        return MALELF_SUCCESS;
}

_u32 malelf_binary_copy_data(MalelfBinary *dest,
                            MalelfBinary *src,
                            _u32 offset_start,
                            _u32 offset_end)
{
        _u32 old_size = dest->size;

        if (dest->alloc_type != MALELF_ALLOC_MALLOC) {
                if (dest->mem == NULL) {
                        dest->alloc_type = MALELF_ALLOC_MALLOC;
                        return malelf_binary_copy_data(dest,
                                                       src,
                                                       offset_start,
                                                       offset_end);
                } else {
                        return MALELF_ENOT_ALLOC_MALLOC;
                }
        }

        if (offset_end == 0) {
                offset_end = src->size;
        }

        dest->size += offset_end - offset_start;
        dest->mem = malelf_realloc(dest->mem, dest->size);
        if (NULL == dest->mem) {
                return MALELF_EALLOC;
        }

        memcpy(dest->mem + old_size,
               src->mem + offset_start,
               offset_end - offset_start);

        return MALELF_SUCCESS;
}

static _i32 _malelf_binary_malloc_load(MalelfBinary *bin)
{
        _i16 n = 0;
        _u32 i = 0;
        bin->mem = malloc(bin->size * sizeof(_u8));
        if (NULL == bin->mem) {
                MALELF_DEBUG_ERROR("Failed to alloc '%u' bytes of "
                                   "binary '%s'",
                                   bin->size,
                                   bin->fname);
                return MALELF_EALLOC;
        }

        /* read the file byte by byte */
        while ((n = read(bin->fd, bin->mem + i, 1)) > 0 && ++i);

        if (-1 == n) {
                int error = errno;
                MALELF_DEBUG_ERROR("Failed to read bytes of binary "
                                   "'%s' from filesystem",
                                   bin->fname);
                return error;
        }

        MALELF_DEBUG_INFO("Binary '%s' mapped in memory with mmap(2)",
                          bin->fname);
        return MALELF_SUCCESS;
}

_i32 malelf_binary_openw(MalelfBinary *bin, char *fname)
{
        return _malelf_binary_open(bin,
                                   fname,
                                   O_RDWR | O_CREAT | O_TRUNC);
}

_i32 malelf_binary_open(MalelfBinary *bin, char *fname)
{
        assert(fname != NULL);
        assert(bin != NULL);

        MALELF_DEBUG_INFO("Opening file '%s'.",
                          fname);

        _i32 result = _malelf_binary_open(bin, fname, O_RDONLY);
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
                return MALELF_EUNKNOWN_ALLOC_TYPE;
        }

        result = malelf_binary_check_elf_magic(bin);

        if (bin->class < MALELF_FLAT) {
                if (MALELF_SUCCESS != result) {
                        MALELF_DEBUG_ERROR("MalelfBinary of type ELF but "
                                     "file '%s' isn't ELF.", fname);
                        return result;
                }

                result = malelf_binary_map(bin);
                if (MALELF_SUCCESS != result) {
                        MALELF_DEBUG_ERROR("Failed to map binary '%s' in "
                                           "memory", bin->fname);
                        return result;
                }
        } else {
                if (MALELF_SUCCESS == result) {
                        MALELF_DEBUG_WARN("MalelfBinary of type FLAT but"
                                          " file '%s' detected as valid"
                                          " ELF. Please check the file.",
                                          bin->fname);
                }

                result = MALELF_SUCCESS;
        }

        MALELF_DEBUG_INFO("Binary '%s' opened and mapped in memory",
                          bin->fname);

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

        MALELF_DEBUG_INFO("Binary '%s' closed", bin->fname);
        _malelf_binary_cleanup(bin);

        return error;
}

/**
 * Functions to get other informations of ELF
 */

static _u32 _malelf_binary_get_segment_32(MalelfBinary *bin,
                                          _u32 segment_idx,
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

        segment->type = phdr32->p_type;
        segment->class = bin->class;
        segment->index = segment_idx;
        segment->size = phdr32->p_filesz;
        segment->offset = phdr32->p_offset;
        segment->mem = bin->mem + phdr32->p_offset;
        segment->phdr = &stphdr;

        return MALELF_SUCCESS;
}

static _u32 _malelf_binary_get_segment_64(MalelfBinary *bin,
                                          _u32 segment_idx,
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

        segment->type = phdr64->p_type;
        segment->class = bin->class;
        segment->index = segment_idx;
        segment->offset = phdr64->p_offset;
        segment->size = phdr64->p_filesz;
        segment->mem = bin->mem + phdr64->p_offset;
        segment->phdr = &stphdr;

        return MALELF_SUCCESS;
}

_u32 malelf_binary_get_segment(MalelfBinary *bin,
                               _u32 segment_idx,
                               MalelfSegment *segment)
{
        int error = MALELF_SUCCESS;

        assert(NULL != bin);
        assert(NULL != bin->mem);

        switch (bin->class) {
        case MALELF_ELF32:
                error = _malelf_binary_get_segment_32(bin,
                                                      segment_idx,
                                                      segment);
                break;
        case MALELF_ELF64:
                error = _malelf_binary_get_segment_64(bin,
                                                      segment_idx,
                                                      segment);
                break;
        default:
                error = MALELF_EINVALID_CLASS;
        }

        return error;
}

inline _u32 _malelf_binary_get_section_name32(MalelfBinary *bin,
                                               _u32 section_idx,
                                               char **name)
{
        MalelfShdr ushdr;
        Elf32_Shdr *shdr32;
        Elf32_Shdr *shstrtab;
        _u32 error;

        error = malelf_binary_get_shdr(bin, &ushdr);

        if (MALELF_SUCCESS != error) {
                return error;
        }

        shdr32 = ushdr.uhdr.h32;
        shdr32 += section_idx;
        _u32 strndx = bin->ehdr.uhdr.h32->e_shstrndx;
        if (strndx > bin->ehdr.uhdr.h32->e_shnum) {
                return MALELF_ESHSTRNDX_CORRUPTED;
        }

        shstrtab = &bin->shdr.uhdr.h32[strndx];
        if (shstrtab->sh_offset > bin->size) {
                return MALELF_ESHSTRTAB_OFFSET_OUT_OF_RANGE;
        }

        *name = (char *)(bin->mem + shstrtab->sh_offset + shdr32->sh_name);

        return MALELF_SUCCESS;
}

inline _u32 _malelf_binary_get_section_name64(MalelfBinary *bin,
                                               _u32 section_idx,
                                               char **name)
{
        MalelfShdr ushdr;
        Elf64_Shdr *shdr64;
        Elf64_Shdr *shstrtab;
        _u32 error;

        error = malelf_binary_get_shdr(bin, &ushdr);

        if (MALELF_SUCCESS != error) {
                return error;
        }

        shdr64 = ushdr.uhdr.h64;
        shdr64 += section_idx;
        _u32 strndx = bin->ehdr.uhdr.h64->e_shstrndx;
        if (strndx > bin->ehdr.uhdr.h64->e_shnum) {
                return MALELF_ESHSTRNDX_CORRUPTED;
        }

        shstrtab = &bin->shdr.uhdr.h64[strndx];
        if (shstrtab->sh_offset > bin->size) {
                return MALELF_ESHSTRTAB_OFFSET_OUT_OF_RANGE;
        }

        *name = (char *)(bin->mem +
                         shstrtab->sh_offset + shdr64->sh_name);

        return MALELF_SUCCESS;
}

_u32 malelf_binary_get_section_name(MalelfBinary *bin,
                                     _u32 section_idx,
                                     char **name)
{
        int error = MALELF_SUCCESS;

        switch (bin->class) {
        case MALELF_ELF32: {
                error = _malelf_binary_get_section_name32(bin,
                                                          section_idx,
                                                          name);
                return error;
        }
        case MALELF_ELF64: {
                error = _malelf_binary_get_section_name64(bin,
                                                          section_idx,
                                                          name);
                return error;
        }
        }

        return MALELF_EINVALID_CLASS;
}

static _u32 _malelf_binary_get_section32(_u32 section_idx,
                                         MalelfBinary *bin,
                                         MalelfSection *section)
{
        _u32 error = MALELF_SUCCESS;
        Elf32_Shdr *shdr32;

        MalelfShdr ushdr;

        error = malelf_binary_get_shdr(bin, &ushdr);

        if (error != MALELF_SUCCESS) {
                return error;
        }

        shdr32 = ushdr.uhdr.h32;
        shdr32 += section_idx;

        error = malelf_binary_get_section_name(bin,
                                                section_idx,
                                                &section->name);

        if (MALELF_SUCCESS != error) {
                return error;
        }

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

        error = malelf_binary_get_section_name(bin,
                                                section_idx,
                                                &section->name);

        if (MALELF_SUCCESS != error) {
                return error;
        }

        section->offset = shdr64->sh_offset;
        section->size = shdr64->sh_size;
        return MALELF_SUCCESS;
}

_u32 malelf_binary_get_section(MalelfBinary *bin,
                               _u32 section_idx,
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

static _u32 _malelf_binary_get_section_by_name32(MalelfBinary *bin,
                                                 const char *name,
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

                char *section_name = NULL;
                error = malelf_binary_get_section_name(bin,
                                                       i,
                                                       &section_name);
                if (MALELF_SUCCESS != error) {
                        return error;
                }

                if (section_name != NULL && !strcmp(name, section_name)) {
                        return _malelf_binary_get_section32(i, bin, section);
                }
        }
        return error;
}

_u32 _malelf_binary_get_section_by_name64(MalelfBinary *bin,
                                          const char *name,
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

                char *section_name = NULL;
                error = malelf_binary_get_section_name(bin,
                                                       i,
                                                       &section_name);
                if (MALELF_SUCCESS != error) {
                        return error;
                }

                if (section_name != NULL && !strcmp(name, section_name)) {
                        return _malelf_binary_get_section64(i,
                                                            bin,
                                                            section);
                }
        }

        return error;
}

_u32 malelf_binary_get_section_by_name(MalelfBinary *bin,
                                       const char *name,
                                       MalelfSection *section)
{
        int error = MALELF_SUCCESS;
        assert(NULL != name && NULL != bin && NULL != bin->mem);


        switch (bin->class) {
        case MALELF_ELF32:
                error = _malelf_binary_get_section_by_name32(bin,
                                                             name,
                                                             section);
                break;
        case MALELF_ELF64:
                error = _malelf_binary_get_section_by_name64(bin,
                                                             name,
                                                             section);
                break;
        default:
                error = MALELF_EINVALID_CLASS;
        }

        return error;
}

_u32 malelf_binary_write_ehdr(MalelfBinary *bin)
{
        _u32 error = MALELF_SUCCESS;

        switch (bin->class) {
        case MALELF_ELF32:
                error = malelf_write(bin->fd, bin->mem, sizeof (Elf32_Ehdr));
                break;
        case MALELF_ELF64:
                error = malelf_write(bin->fd, bin->mem, sizeof (Elf64_Ehdr));
                break;
        default:
                error = MALELF_EINVALID_CLASS;
        }

        return error;
}

inline _u32 _malelf_binary_write_phdr32(MalelfBinary *bin)
{
        Elf32_Ehdr *ehdr = (Elf32_Ehdr *) MALELF_ELF_DATA(&bin->ehdr);
        Elf32_Phdr *phdr = (Elf32_Phdr *) MALELF_ELF_DATA(&bin->phdr);
        _u32 i = 0, error = MALELF_SUCCESS;

        lseek(bin->fd, ehdr->e_phoff, SEEK_SET);

        /* Writing PHDR's */
        for (i = 0; i < ehdr->e_phnum; i++) {
                Elf32_Phdr *p = phdr + i;
                error = malelf_write(bin->fd, (_u8*) p, sizeof (Elf32_Phdr));

                if (MALELF_SUCCESS != error) {
                        return error;
                }
        }

        return error;
}

inline _u32 _malelf_binary_write_phdr64(MalelfBinary *bin)
{
        Elf64_Ehdr *ehdr = (Elf64_Ehdr *) MALELF_ELF_DATA(&bin->ehdr);
        Elf64_Phdr *phdr = (Elf64_Phdr *) MALELF_ELF_DATA(&bin->phdr);
        _u32 i = 0, error = MALELF_SUCCESS;

        lseek(bin->fd, ehdr->e_phoff, SEEK_SET);

        /* Writing PHDR's */
        for (i = 0; i < ehdr->e_phnum; i++) {
                Elf64_Phdr *p = phdr + i;
                error = malelf_write(bin->fd, (_u8*) p, sizeof (Elf64_Phdr));

                if (MALELF_SUCCESS != error) {
                        return error;
                }
        }

        return error;
}


_u32 malelf_binary_write_phdr(MalelfBinary *bin)
{
        _u32 error = MALELF_SUCCESS;

        switch (bin->class) {
        case MALELF_ELF32:
                error = _malelf_binary_write_phdr32(bin);
                break;
        case MALELF_ELF64:
                error = _malelf_binary_write_phdr64(bin);
                break;
        default:
                error = MALELF_EINVALID_CLASS;
        }

        return error;
}

inline _u32 _malelf_binary_write_shdr32(MalelfBinary *bin)
{
        _u32 error = MALELF_SUCCESS;
        _u32 i, ehdr_shnum, ehdr_shoff;
        Elf32_Shdr *shdr = MALELF_ELF_DATA(&bin->shdr);

        assert(NULL != shdr);

        if ((error = malelf_ehdr_get_shnum(&bin->ehdr,
                                           &ehdr_shnum)) != MALELF_SUCCESS ||
            (error = malelf_ehdr_get_shoff(&bin->ehdr,
                                           &ehdr_shoff)) != MALELF_SUCCESS) {
                return error;
        }

        lseek(bin->fd, ehdr_shoff, SEEK_SET);

        for (i = 0; i < ehdr_shnum; i++) {
                Elf32_Shdr *s = shdr + i;
                error = malelf_write(bin->fd,
                                     (_u8 *) s,
                                     sizeof(Elf32_Shdr));
                if (MALELF_SUCCESS != error) {
                        return error;
                }
        }

        return error;
}

inline _u32 _malelf_binary_write_shdr64(MalelfBinary *bin)
{
        _u32 error = MALELF_SUCCESS;
        _u32 i;
        _u32 ehdr_shnum, ehdr_shoff;
        Elf64_Shdr *shdr = MALELF_ELF_DATA(&bin->shdr);

        assert(NULL != shdr);

        if ((error = malelf_ehdr_get_shnum(&bin->ehdr,
                                           &ehdr_shnum)) != MALELF_SUCCESS ||
            (error = malelf_ehdr_get_shoff(&bin->ehdr,
                                           &ehdr_shoff)) != MALELF_SUCCESS) {
                return error;
        }

        lseek(bin->fd, ehdr_shoff, SEEK_SET);

        for (i = 0; i < ehdr_shnum; i++) {
                Elf64_Shdr *s = shdr + i;
                error = malelf_write(bin->fd,
                                     (_u8 *) s,
                                     sizeof(Elf64_Shdr));
                if (MALELF_SUCCESS != error) {
                        return error;
                }
        }

        return error;
}

_u32 malelf_binary_write_shdr(MalelfBinary *bin)
{
        _u32 error = MALELF_SUCCESS;

        switch (bin->class) {
        case MALELF_ELF32:
                error = _malelf_binary_write_shdr32(bin);
                break;
        case MALELF_ELF64:
                error = _malelf_binary_write_shdr64(bin);
                break;
        default:
                error = MALELF_EINVALID_CLASS;
        }

        return error;
}

/**
 * Write a MalelfBinary file on disk,
 *
 * The algorithm is:
 * 1- Create the file with the length of bin->size (zero'ed);
 * 2- Seek to the begin and write EHDR;
 * 3- Seek to the ehdr->e_phoff and write all phts;
 * 4- If the binary has SHDR:
 *     1- For all shts, write the section content to disk;
 * 5- Else, if the binary has PHDR:
 *     1- For all phts, write the segment content to disk;
 * 6- Seek to ehdr->e_shoff (if not zero);
 * 7- Write the SHT;
 * 8- Write everything between SHT and bin->size;
 */
_u32 _malelf_binary_write_elf(MalelfBinary *bin)
{
        _u32 error = MALELF_SUCCESS;
        _u32 i;
        _u32 ehdr_shnum;
        _u32 ehdr_shoff;
        _u32 ehdr_phoff;
        _u32 ehdr_phnum;
        _u8 phdr_size;

        /* We're expecting that bin->size have the correct size of the
           binary to write. If not, this approuch will not work ...
           Here, we truncate the binary to the specified length and then
           we seek to the position to write the data. */
        error = ftruncate(bin->fd, bin->size);

        lseek(bin->fd, 0, SEEK_SET);

        /* Writing EHDR */
        error = malelf_binary_write_ehdr(bin);

        if (MALELF_SUCCESS != error) {
                return error;
        }

        error = malelf_binary_write_phdr(bin);

        if (error != MALELF_SUCCESS) {
                return error;
        }

        if ((error = malelf_ehdr_get_shnum(&bin->ehdr,
                                           &ehdr_shnum)) != MALELF_SUCCESS ||
            (error = malelf_ehdr_get_shoff(&bin->ehdr,
                                           &ehdr_shoff)) != MALELF_SUCCESS ||
            (error = malelf_ehdr_get_phoff(&bin->ehdr,
                                           &ehdr_phoff)) != MALELF_SUCCESS ||
            (error = malelf_ehdr_get_phnum(&bin->ehdr,
                                           &ehdr_phnum)) != MALELF_SUCCESS) {
                return error;
        }

        phdr_size = MALELF_PHDR_SIZE(bin->class);

        /* PHDR and SHDR are'nt always required.
           Executable file doesn't need a SHT ...
           Relocatable file doesn't need a PHT ...

           This function allows the write of partial MalelfBinary objects
           created by malelf_binary_create_elf_* functions.

           Binaries written in assembly could'nt have a SHT.
           The section header table can be ommited for size performance.
           Only EHDR and PHT is required to ET_EXEC binaries.
        */

        /* Testing if the binary have SHT */
        if (ehdr_shnum != 0 &&
            ehdr_shoff > (ehdr_phoff + (phdr_size * ehdr_phnum)) &&
            ehdr_shoff < bin->size) {
                /* Writing sections */
                for (i = 0; i < ehdr_shnum; i++) {
                        MalelfSection section;

                        error = malelf_binary_get_section(bin, i, &section);

                        if (MALELF_SUCCESS != error) {
                                MALELF_DEBUG_WARN("Failed to get section"
                                                  " %u from binary '%s'",
                                                  i,
                                                  bin->fname);
                                return error;
                        }

                        if (section.type == SHT_NULL || section.size == 0) {
                                /* skipping SHT_NULL */
                                continue;
                        }

                        lseek(bin->fd, section.offset, SEEK_SET);

                        error = malelf_write(bin->fd,
                                             bin->mem + section.offset,
                                             section.size);

                        if (MALELF_SUCCESS != error) {
                                MALELF_DEBUG_ERROR("Failed to write "
                                                   "section %u of binary"
                                                   " '%s'",
                                                   i, bin->fname);
                                return error;
                        }
                }

                /* Writing SHT */
                error = malelf_binary_write_shdr(bin);

                if (MALELF_SUCCESS != error) {
                        return error;
                }

                _u32 sht_end = ehdr_shoff +
                        MALELF_SHDR_SIZE(bin->class) * ehdr_shnum;

                /* writing the remaining data (or virus ?) */
                if ((sht_end + 1) < bin->size) {
                        error = malelf_write(bin->fd,
                                             bin->mem + sht_end,
                                             (bin->size - (sht_end + 1)));

                        if (MALELF_SUCCESS != error) {
                                MALELF_DEBUG_ERROR("Failed to write "
                                                   "remaining bytes of "
                                                   "binary '%s'.",
                                                   bin->fname);
                                return error;
                        }
                }
        } else {
                _u32 last_offset = 0;
                _u32 last_size = 0;
                /* writing binary content using the program headers */
                for (i = 0; i < ehdr_phnum; i++) {
                        MalelfSegment segment;

                        error = malelf_binary_get_segment(bin, i, &segment);

                        if (segment.type == PT_NULL)
                                continue;

                        last_offset = segment.offset;
                        last_size = segment.size;

                        lseek(bin->fd, segment.offset, SEEK_SET);
                        error = malelf_write(bin->fd,
                                             bin->mem + segment.offset,
                                             segment.size);

                        if (MALELF_SUCCESS != error) {
                                return error;
                        }
                }

                if (last_offset > 0 &&
                    (last_offset + last_size + 1) < bin->size) {
                        _u32 last_segment_end = last_offset + last_size;
                        error = malelf_write(bin->fd,
                                             bin->mem +
                                             last_segment_end,
                                             bin->size -
                                             (last_segment_end + 1));

                        if (MALELF_SUCCESS != error) {
                                return error;
                        }
                }
        }

        return error;
}

_u32 malelf_binary_write_elf(MalelfBinary *bin, const char *fname)
{
        int error = MALELF_SUCCESS;

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
                        error = errno;
                        MALELF_DEBUG_ERROR("Failed to backup binary "
                                           "'%s' in '%s'",
                                           bin->fname,
                                           bkpfile);
                        return error;
                }

                bin->bkpfile = bkpfile;
        }

        bin->fd = open(bin->fname, O_RDWR|O_CREAT|O_TRUNC, 0755);
        if (bin->fd == -1) {
                error = errno;
                MALELF_DEBUG_ERROR("Failed to open file '%s' to write.",
                                   bin->fname);
                return error;
        }

        return _malelf_binary_write_elf(bin);
}

/**
 * Write the binary based on value in bin->mem and bin->size.
 */
_u32 _malelf_binary_write(MalelfBinary *bin)
{
        _u32 error;
        assert (bin->size > 0);
        assert (bin->fd != -1);

        error = malelf_write(bin->fd, bin->mem, bin->size);
        if (MALELF_SUCCESS != error) {
                MALELF_DEBUG_ERROR("Failed to write '%u' bytes to "
                                   "binary '%s'",
                                   bin->size,
                                   bin->fname);
                return error;
        }

        return error;
}

_u32 malelf_binary_create(MalelfBinary *bin, _u8 overwrite)
{
        int error = MALELF_SUCCESS;

        struct stat st_info;

        assert(NULL != bin);

        if (bin->fd && bin->fd != -1) {
                close(bin->fd);
        }

        if (0 == stat(bin->fname, &st_info) &&
            st_info.st_size > 0 && !overwrite) {
                /* file exists... The boss doesn't want to overwrite. */
                return MALELF_EFILE_EXISTS;
        }

        bin->fd = open(bin->fname, O_RDWR|O_CREAT|O_TRUNC, 0755);
        if (bin->fd == -1) {
                error = errno;
                MALELF_DEBUG_ERROR("Failed to open file '%s' to write.",
                                   bin->fname);
                return error;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_binary_write(MalelfBinary *bin,
                         char *fname,
                         _u8 overwrite)
{
        _u32 error;

        assert (NULL != fname &&
                NULL != bin);

        bin->fname = fname;

        error = malelf_binary_create(bin, overwrite);

        if (MALELF_SUCCESS != error) {
                return error;
        }

        return _malelf_binary_write(bin);
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

        MALELF_DEBUG_INFO("i386 template ELF header created.");
        return error;
}

_u32 malelf_binary_create_elf_exec64(MalelfBinary *bin)
{
        _u32 error = MALELF_SUCCESS;
        Elf64_Ehdr *ehdr;

        bin->mem = malelf_malloc(sizeof (Elf64_Ehdr));
        if (!bin->mem) {
                return MALELF_EALLOC;
        }

        bin->alloc_type = MALELF_ALLOC_MALLOC;
        bin->size = sizeof (Elf64_Ehdr);
        bin->class = MALELF_ELF64;

        ehdr = (Elf64_Ehdr *) bin->mem;
        ehdr->e_ident[0] = ELFMAG0;
        ehdr->e_ident[1] = ELFMAG1;
        ehdr->e_ident[2] = ELFMAG2;
        ehdr->e_ident[3] = ELFMAG3;
        ehdr->e_ident[4] = ELFCLASS64;
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
        ehdr->e_machine = EM_X86_64;
        ehdr->e_version = EV_CURRENT;
        ehdr->e_entry = 0x00;
        ehdr->e_phoff = 0x00;
        ehdr->e_shoff = 0x00;
        ehdr->e_flags = 0x00;
        ehdr->e_ehsize = sizeof (Elf64_Ehdr);
        ehdr->e_phentsize = 0x00;
        ehdr->e_phnum = 0x00;
        ehdr->e_shentsize = 0x00;
        ehdr->e_shnum = 0x00;
        ehdr->e_shstrndx = SHN_UNDEF;

        _malelf_binary_map_ehdr(bin);

        MALELF_DEBUG_INFO("x86_64/AMD64 template ELF header created.");
        return error;
}

_u32 malelf_binary_create_elf_exec(MalelfBinary *bin, _u8 class)
{
        switch (class) {
        case MALELF_ELF32:
                return malelf_binary_create_elf_exec32(bin);
                break;
        case MALELF_ELF64:
                return malelf_binary_create_elf_exec64(bin);
                break;
        }

        return MALELF_EINVALID_CLASS;
}

_u32 malelf_binary_add_phdr32(MalelfBinary *bin, Elf32_Phdr *new_phdr)
{
        Elf32_Ehdr *ehdr;
        _u16 n_phdrs = 0;
        _u32 new_phdr_offset = 0;

        assert(NULL != bin->mem);
        assert(bin->size > 0);
        assert(NULL != bin->ehdr.uhdr.h32);
        assert(NULL != new_phdr);

        MALELF_DEBUG_INFO("Adding phdr");

        ehdr = MALELF_ELF_DATA(&bin->ehdr);
        assert(NULL != ehdr);

        if (ehdr->e_phoff == 0x00 || ehdr->e_phnum == 0x00) {
                /* If the binary doesn't have program headers yet,
                   we need set the initial stuff of EHDR ... */

                /* Here we are good boys ... let's set a good value for
                   program headers offset.
                   Feel free to hack this, like overlapping a bit
                   of ehdr ... hehe */
                ehdr->e_phoff = sizeof (Elf32_Ehdr); /* 52 bytes */
                ehdr->e_phentsize = sizeof (Elf32_Phdr);
                ehdr->e_phnum = 0x00;
        }

        /* Actual number of program headers */
        n_phdrs = ehdr->e_phnum;

        bin->mem = malelf_realloc(bin->mem,
                                  bin->size +
                                  sizeof(Elf32_Phdr));
        if (!bin->mem) {
                MALELF_DEBUG_ERROR("Failed to alloc '%u' bytes for "
                                   "new program header entry.",
                                   sizeof(Elf32_Phdr));
                return MALELF_EALLOC;
        }

        bin->size += sizeof(Elf32_Phdr);
        new_phdr_offset = (_u32) ehdr->e_phoff +
          (sizeof (Elf32_Phdr) * n_phdrs);

        assert (bin->size >= new_phdr_offset);
        assert (bin->size == (new_phdr_offset + sizeof (Elf32_Phdr)));

        MALELF_DEBUG_INFO("New phdr info: (current phnum: %u, "
                          "current size: %u, new offset: %u",
                          n_phdrs,
                          bin->size,
                          new_phdr_offset);

        memcpy(bin->mem + new_phdr_offset,
               new_phdr,
               sizeof (Elf32_Phdr));

        ehdr->e_phnum++;

        _malelf_binary_map_phdr(bin);

        MALELF_DEBUG_INFO("New program header added. (type=%u, address="
                          "0x%08x, size=%u)",
                          new_phdr->p_type,
                          new_phdr->p_vaddr,
                          new_phdr->p_filesz);

        return MALELF_SUCCESS;
}
