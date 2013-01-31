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

#ifndef MALELF_UTIL_H
#define MALELF_UTIL_H

#include <stdio.h>
#include <stdarg.h>
#include "types.h"

#define MAX_LOG_BUFFER 1024

/**
 * Macros
 */
#define LOG_RAW malelf_say
#define SAY if(!malelf_quiet_mode) malelf_say
#define LOG LOG_RAW
#define LOG_SUCCESS malelf_success
#define LOG_VERBOSE_SUCCESS LOG_SUCCESS
#define LOG_ERROR malelf_error
#define LOG_WARN malelf_warn

#define MALELF_UNUSED(var) (void*)var

extern int malelf_log(FILE *fd, const char* prefix, const char* format, va_list args);
extern int malelf_print(FILE *fd, const char* format, ...);
extern int malelf_say(const char* format, ...);
extern int malelf_success(const char* format, ...);
extern int malelf_error(const char* format, ...);
extern int malelf_warn(const char* format, ...);
extern void* malelf_malloc(_u32 size);
extern void* malelf_realloc(void* pointer, _u32 new_size);

/*! Dumps the raw memory in hex
 *
 */
extern _u32 malelf_util_dump(_u8 *mem, _u32 size);

extern _u32 malelf_write(int fd, _u8 *mem, _u32 size);

#endif

