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

#ifndef MALELF_SHELLCODE_H
#define MALELF_SHELLCODE_H

#include <malelf/binary.h>


MALELF_BEGIN_DECLS


/*!
 * 
 * \param bin A valid MalelfBinary object.
 *
 * \return MALELF_SUCCESS if the operation succeeded,
 *         otherwise an ERROR.
 */
extern _u32 malelf_shellcode_dump(MalelfBinary *bin);


/*!
 * 
 * \param bin A valid MalelfBinary object.
 * \param fp
 *
 * \return MALELF_SUCCESS if the operation succeeded,
 *         otherwise an ERROR.
 */
extern _u32 malelf_shellcode_get_c_string(FILE *fp, MalelfBinary *bin);


/*!
 *
 * \param dest
 * \param src
 * \param magic_offset
 * \param original_entry_point
 * \param magic_bytes
 *
 * \return MALELF_SUCCESS if the operation succeeded,
 *         otherwise an ERROR.
 */
extern _u32 malelf_shellcode_create_flat(MalelfBinary *dest,
                                         MalelfBinary *src,
                                         _u32 *magic_offset,
                                         unsigned long int original_entry_point,
                                         unsigned long int magic_bytes);


/*!
 *
 * \param fd_o
 * \param in_size
 * \param fd_i
 * \param original_entry_point
 *
 * \return MALELF_SUCCESS if the operation succeeded,
 *         otherwise an ERROR.
 */
extern _i32 malelf_shellcode_create_c(FILE* fd_o,
                                      int in_size,
                                      FILE* fd_i,
                                      unsigned long int original_entry_point);


MALELF_END_DECLS


#endif
