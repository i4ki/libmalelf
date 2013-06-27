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

_u32 malelf_disas(MalelfDisas *obj)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }

        while (ud_disassemble(&obj->ud_obj)) {
                fprintf(stdout, "\t%s\n", ud_insn_asm(&obj->ud_obj));
        }

        return MALELF_SUCCESS;
}        


