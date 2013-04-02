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

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <assert.h>

#include <elf.h>

#include <malelf/types.h>
#include <malelf/error.h>
#include <malelf/binary.h>
#include <malelf/defines.h>
#include <malelf/shellcode.h>

_u32 malelf_shellcode_dump(MalelfBinary *bin)
{
	assert(NULL != bin && NULL != bin->mem && bin->size > 0);

	return malelf_dump(bin->mem, bin->size);
}

_u32 malelf_shellcode_get_c_string(FILE *fp, MalelfBinary *bin)
{
	_u32 i;
	assert(NULL != bin && NULL != bin->mem && bin->size > 0);

	for (i = 0; i < bin->size; i++) {
		fprintf(fp, "\\x%02x", bin->mem[i]);
	}

	return MALELF_SUCCESS;
}

