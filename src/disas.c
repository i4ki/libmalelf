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
#include <string.h>

#include <udis86.h>

#include <malelf/types.h>
#include <malelf/error.h>
#include <malelf/disas.h>


_u32 malelf_disas_init(MalelfDisas *obj, MalelfBinary *bin)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }

        if (NULL == bin) {
                return MALELF_ERROR;
        }

        ud_init(&obj->ud_obj);

        switch (bin->class) {
        case MALELF_ELF32:
                ud_set_mode(&obj->ud_obj, 32);
                break;
        case MALELF_ELF64:
                ud_set_mode(&obj->ud_obj, 64);
                break;
        }

        ud_set_syntax(&obj->ud_obj, UD_SYN_INTEL);

        return MALELF_SUCCESS;
}


_u32 malelf_disas_set_syntax_intel(MalelfDisas *obj)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }

        ud_set_syntax(&obj->ud_obj, UD_SYN_INTEL);

        return MALELF_SUCCESS;
}

_u32 malelf_disas_set_syntax_att(MalelfDisas *obj)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }

        ud_set_syntax(&obj->ud_obj, UD_SYN_ATT);

        return MALELF_SUCCESS;
}



static _u32 _malelf_disas64(MalelfDisas *obj,
                            MalelfBinary *bin,
                            const char *section_name)
{
        MalelfEhdr ehdr;
        MalelfShdr shdr;
        Elf64_Shdr *sections;
        unsigned int i;
        _u32 shnum;
        _u32 shstrndx;
        char *sec_name;

        if (NULL == obj) {
                return MALELF_ERROR;
        }

        if (NULL == bin) {
                return MALELF_ERROR;
        }

        malelf_binary_get_ehdr(bin, &ehdr);
        malelf_binary_get_shdr(bin, &shdr);
        malelf_ehdr_get_shnum(&ehdr, &shnum);
        malelf_ehdr_get_shstrndx(&ehdr, &shstrndx);

        sections = shdr.uhdr.h64;
        for (i = 0; i < shnum; i++) {
                Elf64_Shdr *s = &sections[i];

                if (s->sh_type == SHT_NULL) {
                        continue;
                }

                if (0x00 != shstrndx) {
                        malelf_binary_get_section_name(bin, i, &sec_name);
                }

                if (NULL != section_name) {
                        if (0 != strncmp(sec_name,
                                         section_name,
                                         strlen(section_name))) {
                                continue;
                        }
                }

                if (NULL != sec_name) {
                        _u8* mem = bin->mem + s->sh_offset;
                        ud_set_input_buffer(&obj->ud_obj,
                                            (unsigned char* )mem,
                                            s->sh_size);
                        while (ud_disassemble(&obj->ud_obj)) {
                                printf("\t%s\n", ud_insn_asm(&obj->ud_obj));
                        }
                }
        }
        return MALELF_SUCCESS;
}

static _u32 _malelf_disas32(MalelfDisas *obj,
                            MalelfBinary *bin,
                            const char *section_name)
{
        MalelfEhdr ehdr;
        MalelfShdr shdr;
        Elf32_Shdr *sections;
        unsigned int i;
        _u32 shnum;
        _u32 shstrndx;
        char *sec_name;
        _u8 found = 0;

        if (NULL == obj) {
                return MALELF_ERROR;
        }

        if (NULL == bin) {
                return MALELF_ERROR;
        }

        malelf_binary_get_ehdr(bin, &ehdr);
        malelf_binary_get_shdr(bin, &shdr);
        malelf_ehdr_get_shnum(&ehdr, &shnum);
        malelf_ehdr_get_shstrndx(&ehdr, &shstrndx);

        sections = shdr.uhdr.h32;
        for (i = 0; i < shnum; i++) {
                Elf32_Shdr *s = &sections[i];

                if (s->sh_type == SHT_NULL) {
                        continue;
                }

                if (0x00 != shstrndx) {
                        malelf_binary_get_section_name(bin, i, &sec_name);
                }

                if (NULL != section_name) {
                        if (0 != strncmp(sec_name,
                                         section_name,
                                         strlen(section_name))) {
                                continue;
                        }
                }

                if (NULL != sec_name) {
                        found = 1;
                        _u8* mem = bin->mem + s->sh_offset;
                        ud_set_input_buffer(&obj->ud_obj,
                                            (unsigned char* )mem,
                                            s->sh_size);
                        while (ud_disassemble(&obj->ud_obj)) {
                                printf("\t%s\n", ud_insn_asm(&obj->ud_obj));
                        }
                }
        }

        return found ? MALELF_SUCCESS : MALELF_ESECTION_NOT_FOUND;
}

_u32 malelf_disas(MalelfDisas *obj, MalelfBinary *bin, const char *section_name)
{
        _u32 result = MALELF_EINVALID_CLASS;
        if (NULL == obj) {
                return MALELF_ERROR;
        }

        if (NULL == bin) {
                return MALELF_ERROR;
        }

        switch (bin->class) {
        case MALELF_ELF32:
                result = _malelf_disas32(obj, bin, section_name);
                break;
        case MALELF_ELF64:
                result = _malelf_disas64(obj, bin, section_name);
                break;
        }
        return result;
}
