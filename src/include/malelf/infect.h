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


#ifndef INFECT_H
#define INFECT_H

#include <malelf/binary.h>


MALELF_BEGIN_DECLS


/*! Infect ELF using Silio Cesare technique.
 *
 * \param input A valid MalelfBinary object.
 * \param output The ELF infected output.
 * \param parasite The malware user to infect.
 * \param offset_entry_point Parasite entry point.
 *
 * \return MALELF_SUCCESS if the operation succeeded,
 *         otherwise an ERROR.
 */ 
extern _u8 malelf_infect_silvio_padding(MalelfBinary* input,
                                        MalelfBinary* output,
                                        MalelfBinary* parasite,
                                        _u32 offset_entry_point,
                                        _u32 magic_bytes);


/*! Infect ELF using Silio Cesare technique (32 bits).
 *
 * \param input A valid MalelfBinary object.
 * \param output The ELF infected output.
 * \param parasite The malware user to infect.
 * \param offset_entry_point Parasite entry point.
 *
 * \return MALELF_SUCCESS if the operation succeeded,
 *         otherwise an ERROR.
 */ 
extern _u32 malelf_infect_silvio_padding32(MalelfBinary *host,
                                           MalelfBinary *output,
                                           MalelfBinary *parasite,
                                           _u32 offset_entry_point,
                                           _u32 magic_bytes);


/*! Infect ELF using Silio Cesare technique (64 bits).
 *
 * \param input A valid MalelfBinary object.
 * \param output The ELF infected output.
 * \param parasite The malware user to infect.
 * \param offset_entry_point Parasite entry point.
 *
 * \return MALELF_SUCCESS if the operation succeeded,
 *         otherwise an ERROR.
 */ 
extern _u32 malelf_infect_silvio_padding64(MalelfBinary *host,
                                           MalelfBinary *output,
                                           MalelfBinary *parasite,
                                           _u32 offset_entry_point,
                                           _u32 magic_bytes);


MALELF_END_DECLS


#endif
