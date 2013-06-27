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



typedef struct {
        ud_t ud_obj;
} MalelfDisas;

_u32 malelf_disas_init(MalelfDisas *obj, MalelfBinary *bin);

_u32 malelf_disas(MalelfDisas *obj);

_u32 malelf_disas_set_syntax_att(MalelfDisas *obj);

_u32 malelf_disas_set_syntax_intel(MalelfDisas *obj);

