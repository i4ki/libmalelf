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

#endif

