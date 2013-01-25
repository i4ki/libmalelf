/* 
 * The malelf library was written in pure C, with the objective to 
 * provide a quick and easy way a set functions for programmers to 
 * manipulate ELF files. With libmalelf can dissect and infect ELF 
 * files. Evil using this library is the responsibility of the programmer.
 *
 * Author: Tiago Natel de Moura <tiago4orion@gmail.com>
 *
 * Contributor: Daniel Ricardo dos Santos <danielricardo.santos@gmail.com>
 *              Paulo Leonardo Benatto <benatto@gmail.com>
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
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "malelf/error.h"

const char* malelf_strerr[] = {
    "Unknow error", /* MALELF_ERROR */
    "File already closed",
    "Error allocating memory",
    "Binary is NOT ELF",
    "Binary is corrupted",
    "Binary has suspect section names",
    "Missing magic bytes in malware",
    "Invalid offset for returned entry point in malware",
    "Disassembly error.",
    "The file is empty",
    "The buffer tried to set on MalelfEhdr is bigger than the ElfX_Ehdr structure.",
    "Invalid ELF Class"    
};

const char* malelf_strerror(int code) {
    return malelf_strerr[(code - MALELF_ERROR)];
}

void _malelf_perror(int code, const char* func, const char* file, int line) {
  if (code >= 0 && code < MALELF_LAST_ERRNO) {
      LOG_ERROR("[%s][function %s][line %d][code %d] %s\n", file, func, line, code, strerror(code));
  } else if (code >= 0 && code < MALELF_LAST_ERROR) {
      LOG_ERROR("[%s][function %s][line %d][code %d] %s\n", file, func, line, code, malelf_strerror(code));
  } else {
    LOG_ERROR("[%s][function %s][line %d][code %d] %s\n", file, func, line, code, "UNKNOW ERROR");
  }
}
