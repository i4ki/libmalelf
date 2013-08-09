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

#include <udis86.h>

#include "binary.h"
#include "defines.h"


MALELF_BEGIN_DECLS


typedef struct {
        ud_t ud_obj;
} MalelfDisas;

/*! Initialize MalelfDisas object.
 *
 * \param obj A valid MalelfDisas object.
 * \param bin A valid MalelfBinary object.
 *  
 * \return MALELF_SUCCESS if the operation succeeded,
 *         otherwise MALELF_ERROR.
 */
_u32 malelf_disas_init(MalelfDisas *obj, MalelfBinary *bin);


/*! Disassemble.
 *
 * \param obj A valid MalelfDisas object.
 * \param bin A valid MalelfBinary object.
 * \param section_name The section name to disassemble.
 *
 * \return MALELF_SUCCESS if the operation succeeded,
 *         otherwise MALELF_ERROR.
 */
_u32 malelf_disas(MalelfDisas *obj, 
                  MalelfBinary *bin, 
                  const char *section_name);


/*! Set the AT&T syntax.
 *
 * \param obj A valid MalelfDisas object.
 *
 * \return MALELF_SUCCESS if the operation succeeded,
 *         otherwise MALELF_ERROR.
 */
_u32 malelf_disas_set_syntax_att(MalelfDisas *obj);


/*! Set the intel syntax. 
 *
 * \parami obj A valid MalelfDisas object.
 *
 * \return MALELF_SUCCESS if the operation succeeded, 
 *         otherwise MALELF_ERROR.
 */
_u32 malelf_disas_set_syntax_intel(MalelfDisas *obj);


MALELF_END_DECLS
