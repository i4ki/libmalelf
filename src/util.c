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
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include <malelf/util.h>
#include <malelf/error.h>
#include <malelf/debug.h>

extern _u8 malelf_quiet_mode;

int malelf_log(FILE *fd,
               const char *prefix,
               const char *format,
               va_list args)
{
        char outbuf[MAX_LOG_BUFFER];
        int i, error = 0;
        size_t len, len_prefix;

        memset(outbuf, '\0', MAX_LOG_BUFFER);

        i = vsprintf(outbuf, format, args);
        len = strlen(outbuf);
        len_prefix = strlen(prefix);

        if (fwrite(prefix,
                   sizeof(char),
                   strlen(prefix),
                   fd) != len_prefix) {
                error = 1;
                goto out;
        }

        if (fwrite(outbuf, sizeof(char), len, fd) != len) {
                error = 1;
                goto out;
        }

        fflush(fd);

out:
        va_end(args);
        return error ? -1 : i;
}

int malelf_print(FILE *fd, const char *format, ...)
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

int malelf_success(const char *format, ...)
{
        va_list args;
        va_start(args, format);
        return malelf_log(stdout, "[+] ", format, args);
}

int malelf_warn(const char *format, ...)
{
        va_list args;
        va_start(args, format);
        return malelf_log(stderr, "[!] ", format, args);
}

void *malelf_malloc(_u32 size)
{
        void *mem = malloc(size);
        if (NULL != mem) {
                return mem;
        } else {
                malelf_error("Failed to allocate '%d' bytes.\n", size);
                exit(-1);
        }
}

void *malelf_realloc(void *pointer, _u32 new_size)
{
        if (NULL == pointer) {
                pointer = malelf_malloc(new_size);
                return pointer;
        }

        pointer = realloc(pointer, new_size);
        if (NULL == pointer) {
                malelf_error("Failed to realloc '%d' bytes.\n", new_size);
                exit(-1);
        }

        return pointer;
}

/* dump ripped from `hacking - the art of exploitation - joe` */
_u32 malelf_dump(_u8 *mem, _u32 size)
{
        _u8 byte;
        _u32 i, j;

        for (i = 0; i < size; i++) {
                byte = mem[i];
                malelf_say("%02x ", mem[i]);
                if (((i % 16) == 15) || (size - 1 == i)) {
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

                if (3 == tries) {
                        /* IO problems? */
                        error = errno;
                        break;
                }
        }
        return error;
}

/*!
 * Find the offset of the first occurrence of magic number magic_addr
 * in binary_data.
 * The offset returned is at offset_magic param.
 *
 * @return MALELF_SUCCESS if pattern found, MALELF_ERROR otherwises
 */
_u32 malelf_find_magic_number(_u8 *binary_data,
                              _u32 size,
                              union malelf_dword magic_addr,
                              _u32 *offset_magic) {
        _u8 curSearch = 0;
        _u8 found = 0;
        _u32 i = 0;
        *offset_magic = 0;

        if (! (i < size)) {
                MALELF_DEBUG_ERROR("Empty binary data to find magic "
                                   "number...");
                return MALELF_EMISSING_MAGIC_BYTES;
        }

        while(i < size) {
                unsigned hex = binary_data[i];

                if(hex == magic_addr.char_val[curSearch]) {
                        /* found a match */
                        curSearch++;

                        if(curSearch > 3) {
                                /* found the whole magic number */
                                found = 1;
                                *offset_magic = i - 3;
                                MALELF_DEBUG_INFO("Magic number found at"
                                                  "'%d' bytes of malware"
                                                  "\n", *offset_magic);
                                break;
                        }
                } else {
                        /* go back, search for first char */
                        curSearch = 0;
                }

                i++;
        }

        return found ? MALELF_SUCCESS : MALELF_ERROR;
}
