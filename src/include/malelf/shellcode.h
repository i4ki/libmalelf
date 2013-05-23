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

#ifndef MALELF_SHELLCODE_H
#define MALELF_SHELLCODE_H

MALELF_BEGIN_DECLS

#define MALELF_MAGIC_BYTES 0x31333337

/*
 *
 *
 */
extern _u32 malelf_shellcode_dump(MalelfBinary *bin);


/*
 *
 *
 */
extern _u32 malelf_shellcode_get_c_string(FILE *fp, MalelfBinary *bin);

extern _i32 malelf_shellcode_create_flat(FILE* fd_o,
                                         int in_size,
                                         FILE* fd_i,
                                         unsigned long int original_entry_point,
                                         unsigned long int magic_bytes);

extern _i32 malelf_shellcode_create_c(FILE* fd_o,
                                      int in_size,
                                      FILE* fd_i,
                                      unsigned long int original_entry_point);


MALELF_END_DECLS

#endif
