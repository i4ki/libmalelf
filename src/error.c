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
#include <string.h>

#include "malelf/error.h"

const char* malelf_strerr[] = {
        "Unknown error", /* MALELF_ERROR */
        "File already closed",
        "Error allocating memory",
        "Binary is NOT ELF",
        "Binary is corrupted",
        "Binary has suspect section names",
        "Missing magic bytes in malware",
        "Invalid offset for returned entry point in malware",
        "Disassembly error.",
        "The file is empty",
        "The buffer tried to set on MalelfEhdr is bigger\
         than the ElfX_Ehdr structure.",
        "Invalid ELF Class",
        "Unknown allocation type. Probably the MalelfBinary structure "
        "was not instantiated by malelf_binary_init()",
        "File exists... leaving ...",
        "TEXT segment not found in binary. Neither segment has Read\
 and Exec flags.",
        "Alloc type isn't MALELF_ALLOC_MALLOC ... is not possible to\
 realloc",
        "Entry of e_shstrndx in ELF header could be corrupted. The index"
        " is bigger than the number of sections in e_shnum. Verify your "
        "binary.",
        "Offset in binary of Section Header String Table (shstrtab) is "
        "bigger than the size of binary. The file analysed could be "
        "corrupted."
};

const char* malelf_strerror(int code)
{
        return malelf_strerr[(code - MALELF_ERROR)];
}

/* Private method */
void __malelf_perror(int code,
                     const char* func,
                     const char* file,
                     int line)
{
        char * format_error = "[%s][function %s][line %d]"
                                    "[code %d] %s\n";
        char * error_message = "UNKNOW ERROR";

        if (code >= 0 && code < MALELF_LAST_ERRNO) {
                error_message = strerror(code);
        } else if (code >= 0 && code < MALELF_LAST_ERROR) {
                error_message = (char *) malelf_strerror(code);
        }

        LOG_ERROR(format_error,
                  file,
                  func,
                  line,
                  code,
                  error_message);
}
