#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

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
        strncpy(n_format, prefix, strlen(prefix));
        strncat(n_format, format, MAX_LOG_BUFFER - strlen(n_format));
  
        i = vsprintf(outbuf, n_format, args);

        len = strlen(outbuf);
        if (fwrite(outbuf, sizeof(char), len, fd) == len) {
                va_end(args);
                return i;
        } else {
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

void* malelf_malloc(_u32 size)
{
        void *mem = malloc(size);
        if (mem != NULL) {
                return mem;
        } else {
                malelf_error("Failed to allocate '%d' bytes.\n", size);
                exit(-1);
        }
}

void* malelf_realloc(void* pointer, _u32 new_size)
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
