/*
 * The libmalelf is a evil library that could be used for good ! It was
 * developed with the intent to assist in the process of infecting
 * binaries and provide a safe way to analyze malwares.
 *
 * Evil using this library is the responsibility of the programmer.
 *
 * Author:
 *         Tiago Natel de Moura <natel@secplus.com.br>
 *
 * Contributor:
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

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <errno.h>
#include <malelf/debug.h>
#include <malelf/error.h>
#include <malelf/util.h>

#define LOG_BUFSIZE 1024
static _u8 _malelf_debug = 0;
static FILE *_malelf_debug_fd;
static _u8 _malelf_debug_ok = 0;

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
                if (_malelf_debug) {
                        _malelf_debug = 1;
                        _malelf_debug_open_file(malelf_debug_file_env);
                }
        }
}

int malelf_debug(const char * fmt, ...)
{
        va_list args;
        va_start(args, fmt);
        struct tm result;
        time_t ltime; /* calendar time */
        char fmt_out[LOG_BUFSIZE];
        char stime[26];
        int timelen;

        if (!_malelf_debug_ok) {
                malelf_error("Debug not started... You need run "
                             "malelf_debug_init() first!\n");
                return 0;
        }

        bzero(fmt_out, LOG_BUFSIZE);
        bzero(stime, 26);

        ltime=time(NULL); /* get current cal time */
        localtime_r(&ltime, &result);
        asctime_r(&result, stime);

        timelen = strlen(stime);

        strncpy(fmt_out, stime, timelen);
        fmt_out[timelen - 1] = 0;
        strncat(fmt_out, " ", LOG_BUFSIZE - timelen);
        strncat(fmt_out, fmt, (LOG_BUFSIZE - 1) - timelen);
        strncat(fmt_out, "\n",
                (LOG_BUFSIZE - 1) - timelen - strlen(fmt));

        return _malelf_debug ?
                malelf_log(_malelf_debug_fd, "[DEBUG] ", fmt_out, args) :
                0;
}
