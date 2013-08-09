/*
 * The libmalelf is a evil library that could be used for good ! It was
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

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <errno.h>
#include <malelf/debug.h>
#include <malelf/error.h>
#include <malelf/util.h>

#define LOG_BUFSIZE (1024)

_u8 _malelf_debug = 0;
FILE *_malelf_debug_fd;
_u8 _malelf_debug_ok = 0;

void _malelf_debug_open_file(char *fname)
{
        if (fname == NULL) {
                _malelf_debug_fd = MALELF_DEBUG_OUTPUT;
                return;
        }

        _malelf_debug_fd = fopen(fname, "a+");

        if (!_malelf_debug_fd) {
                malelf_error("Error in environment variable "
                             "MALELF_DEBUG_FILE ='%s': ",
                             fname);
                MALELF_PERROR(errno);

                _malelf_debug_fd = MALELF_DEBUG_OUTPUT;
        }
}

void malelf_debug_init()
{
        char *malelf_debug_env = NULL;
        char *malelf_debug_file_env = NULL;

        _malelf_debug = 0;
        _malelf_debug_fd = stderr;
        _malelf_debug_ok = 1;

        malelf_debug_env = getenv("MALELF_DEBUG");
        malelf_debug_file_env = getenv("MALELF_DEBUG_FILE");

        if (malelf_debug_env) {
                _malelf_debug = atoi(malelf_debug_env);
                if (_malelf_debug >= MALELF_DEBUG_LOG_INFO &&
                    _malelf_debug <= MALELF_DEBUG_LOG_CRITICAL) {
                        _malelf_debug_open_file(malelf_debug_file_env);
                } else {
                  _malelf_debug = MALELF_DEBUG_LOG_CRITICAL;
                }
        }
}

void malelf_debug_cleanup()
{
        if (_malelf_debug_fd > stderr)
                fclose(_malelf_debug_fd);
}

/* Private function */
int __malelf_debug(_u8 logcode,
                   const char* func,
                   const char *file,
                   const char *line,
                   const char * fmt,
                   ...)
{
        va_list args;
        va_start(args, fmt);
        struct tm result;
        time_t ltime;
        char temp[256];
        char fmt_out[LOG_BUFSIZE];
        char stime[26];
        int timelen;
        char *prefix;

        if (!_malelf_debug_ok) {
                malelf_error("Debug not started... You need run "
                             "malelf_debug_init() first!\n");
                return 0;
        }

        bzero(temp, 255);
        bzero(fmt_out, LOG_BUFSIZE);
        bzero(stime, 26);

        ltime=time(NULL);
        localtime_r(&ltime, &result);
        asctime_r(&result, stime);

        timelen = strlen(stime);

        strcat(temp, "[");
        strncat(temp, stime, timelen);
        temp[timelen] = 0;
        strcat(temp, "]");
        strcat(temp, "[%s][%s:%s] %s");

        snprintf(fmt_out,
                 LOG_BUFSIZE,
                 temp,
                 func,
                 file,
                 line,
                 fmt);

        fmt_out[LOG_BUFSIZE - 2] = 0;
        strcat(fmt_out, "\n");

        switch (logcode) {
        case MALELF_DEBUG_LOG_NONE:
                prefix = "";
                break;
        case MALELF_DEBUG_LOG_INFO:
                prefix = "[INFO]";
                break;
        case MALELF_DEBUG_LOG_WARN:
                prefix = "[WARN]";
                break;
        case MALELF_DEBUG_LOG_ERROR:
                prefix = "[ERROR]";
                break;
        case MALELF_DEBUG_LOG_CRITICAL:
                prefix = "[CRITICAL]";
                break;
        default:
                prefix = "[INFO]";
        }

        return _malelf_debug ?
                malelf_log(_malelf_debug_fd,
                           prefix,
                           fmt_out,
                           args) :
                           0;
}
