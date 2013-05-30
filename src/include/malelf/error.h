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
 * Contributorss:
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

#ifndef MALELF_ERROR_H
#define MALELF_ERROR_H

#include "util.h"


MALELF_BEGIN_DECLS


#define MAX_MSG_ERROR 255

typedef enum {
  MALELF_SUCCESS = 0,
  MALELF_EPERM,	/* Operation not permitted */
  MALELF_ENOENT	= 2,	/* No such file or directory */
  MALELF_ESRCH	= 3,	/* No such process */
  MALELF_EINTR	= 4,	/* Interrupted system call */
  MALELF_EIO	        = 5,	/* I/O error */
  MALELF_ENXIO	= 6,	/* No such device or address */
  MALELF_E2BIG	= 7,	/* Argument list too long */
  MALELF_ENOEXEC	= 8,	/* Exec format error */
  MALELF_EBADF	= 9,	/* Bad file number */
  MALELF_ECHILD	= 10,	/* No child processes */
  MALELF_EAGAIN	= 11,	/* Try again */
  MALELF_ENOMEM	= 12,	/* Out of memory */
  MALELF_EACCES	= 13,	/* Permission denied */
  MALELF_EFAULT	= 14,	/* Bad address */
  MALELF_ENOTBLK	= 15,	/* Block device required */
  MALELF_EBUSY	= 16,	/* Device or resource busy */
  MALELF_EEXIST	= 17,	/* File exists */
  MALELF_EXDEV	= 18,	/* Cross-device link */
  MALELF_ENODEV	= 19,	/* No such device */
  MALELF_ENOTDIR	= 20,	/* Not a directory */
  MALELF_EISDIR	= 21,	/* Is a directory */
  MALELF_EINVAL	= 22,	/* Invalid argument */
  MALELF_ENFILE	= 23,	/* File table overflow */
  MALELF_EMFILE	= 24,	/* Too many open files */
  MALELF_ENOTTY	= 25,	/* Not a typewriter */
  MALELF_ETXTBSY	= 26,	/* Text file busy */
  MALELF_EFBIG	= 27,	/* File too large */
  MALELF_ENOSPC	= 28,	/* No space left on device */
  MALELF_ESPIPE	= 29,	/* Illegal seek */
  MALELF_EROFS	= 30,	/* Read-only file system */
  MALELF_EMLINK	= 31,	/* Too many links */
  MALELF_EPIPE	= 32,	/* Broken pipe */
  MALELF_EDOM	= 33,	/* Math argument out of domain of func */
  MALELF_ERANGE	= 34,	/* Math result not representable */
  MALELF_LAST_ERRNO  = 35,

  MALELF_ERROR = 40,
  MALELF_ECLOSED = 41,
  MALELF_EALLOC = 42,
  MALELF_ENOT_ELF = 43,
  MALELF_ECORRUPTED = 44,
  MALELF_ESUSPECT_SECTIONS = 45,
  MALELF_EMISSING_MAGIC_BYTES = 46,
  MALELF_EINV_OFFSET_ENTRY = 47,
  MALELF_EDISAS = 48,
  MALELF_EEMPTY_FILE = 49,
  MALELF_EEHDR_OVERFLOW = 50,
  MALELF_EINVALID_CLASS = 51,
  MALELF_EUNKNOWN_ALLOC_TYPE = 52,
  MALELF_EFILE_EXISTS = 53,
  MALELF_ETEXT_SEG_NOT_FOUND = 54,
  MALELF_ENOT_ALLOC_MALLOC = 55,
  MALELF_ESHSTRNDX_CORRUPTED = 56,
  MALELF_ESHSTRTAB_OFFSET_OUT_OF_RANGE = 57,

  MALELF_LAST_ERROR = 58
} malelf_status;


#define MALELF_PERROR(code)\
    __malelf_perror(code, __FUNCTION__, __FILE__, __LINE__)

#define MALELF_FATAL(code)\
    do {\
        MALELF_PERROR(code);\
        LOG_ERROR("Aborting...\n");\
        exit(code);\
    } while(0)


/* Private method */
extern void __malelf_perror(int code,
                            const char* func,
                            const char* file,
                            int line);

/*! Get string error.
 *
 * \param code Error code.
 *
 * \return String error.
 */
extern const char* malelf_strerror(int code);


MALELF_BEGIN_DECLS

#endif
