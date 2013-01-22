#ifndef MALELF_ERROR_H
#define MALELF_ERROR_H

#include "util.h"

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

  MALELF_LAST_ERROR = 52
} malelf_status;

#define malelf_perror(code) _malelf_perror(code, __FUNCTION__, __FILE__, __LINE__)
#define malelf_fatal(code) do {malelf_perror(code); LOG_ERROR("Aborting...\n"); exit(code); } while(0)

extern void _malelf_perror(int code,
                           const char* func,
                           const char* file,
                           int line);
extern const char* malelf_strerror(int code);

#endif
