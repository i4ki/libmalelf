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
#include <strings.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <malelf/util.h>
#include <malelf/error.h>

extern _u8 malelf_quiet_mode;

int malelf_log(FILE* fd,
               const char* prefix,
               const char *format,
               va_list args)
{
        char outbuf[MAX_LOG_BUFFER];
        char n_format[MAX_LOG_BUFFER];
        int i;
        size_t len;

        memset(outbuf, '\0', MAX_LOG_BUFFER);
        memset(n_format, '\0', MAX_LOG_BUFFER);
        strncpy(n_format, prefix, MAX_LOG_BUFFER);
        strncat(n_format, format, MAX_LOG_BUFFER - strlen(n_format));
  
        i = vsprintf(outbuf, n_format, args);

        len = strlen(outbuf);
        if (fwrite(outbuf, sizeof(char), len, fd) == len) {
                va_end(args);
                return i;
        } else {
		va_end(args);
                return  -1;
        }
}

int malelf_print(FILE* fd, const char* format, ...)
{
        va_list args;
        va_start(args, format);
        return malelf_log(fd, "", format, args);
}

int malelf_say(const char *format, ...)
{
        va_list args;
        va_start(args, format);
        return malelf_log(stdout, "", format, args);
}

int malelf_error(const char *format, ...)
{
        va_list args;
        va_start(args, format);
        return malelf_log(stderr, "[-] ", format, args);
}

int malelf_success(const char* format, ...)
{
        va_list args;
        va_start(args, format);
        return malelf_log(stdout, "[+] ", format, args);
}

int malelf_warn(const char* format, ...)
{
        va_list args;
        va_start(args, format);
        return malelf_log(stderr, "[!] ", format, args);
}

void *malelf_malloc(_u32 size)
{
        void *mem = malloc(size);
        if (mem != NULL) {
                return mem;
        } else {
                malelf_error("Failed to allocate '%d' bytes.\n", size);
                exit(-1);
        }
}

void *malelf_realloc(void* pointer, _u32 new_size)
{
        if (pointer == NULL) {
                pointer = malelf_malloc(new_size);
                return pointer;
        }

        pointer = realloc(pointer, new_size);
        if (pointer == NULL) {
                malelf_error("Failed to realloc '%d' bytes.\n", new_size);
                exit(-1);
        }

        return pointer;
}

/* dump ripped from `hacking - the art of exploitation - joe` */
_u32 malelf_util_dump(_u8 *mem, _u32 size)
{
	_u8 byte;
	_u32 i, j;

	for (i = 0; i < size; i++) {
		byte = mem[i];
		malelf_say("%02x ", mem[i]);
		if (((i % 16) == 15) || (i == size - 1)) {
			for (j = 0; j < (15 - (i % 16)); j++) {
				malelf_say("   ");
			}

			malelf_say("| ");

			for (j = (i - (i % 16)); j <= i; j++) {
				byte = mem[j];
				if ((byte > 31) && (byte < 127)) {
					/* ascii char */
					malelf_say("%c", byte);
				} else {
					malelf_say(".");
				}
			}

			malelf_say("\n");
		}
	}

	return MALELF_SUCCESS;
}

_u32 malelf_write(int fd, _u8 *mem, _u32 size) 
{
	int error = MALELF_SUCCESS;
	_u32 bytes_saved = 0;
	_u8 tries = 0;

	while (bytes_saved < size) {
		if (write(fd, mem + bytes_saved, 1) <= 0) {
			tries++;
		} else {
			tries  = 0;
			bytes_saved++;
		}

		if (tries == 3) {
			/* IO problems? */
			error = errno;
			break;
		}
	}

	return error;
}
