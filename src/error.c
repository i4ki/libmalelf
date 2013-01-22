#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "malelf/error.h"

const char* malelf_strerr[] = {
    "Unknow error", /* MALELF_ERROR */
    "File already closed",
    "Error allocating memory",
    "Binary is NOT ELF",
    "Binary is corrupted",
    "Binary has suspect section names",
    "Missing magic bytes in malware",
    "Invalid offset for returned entry point in malware",
    "Disassembly error.",
    "The file is empty",
    "The buffer tried to set on MalelfEhdr is bigger than the ElfX_Ehdr structure.",
    "Invalid ELF Class"    
};

const char* malelf_strerror(int code) {
    return malelf_strerr[(code - MALELF_ERROR)];
}

void _malelf_perror(int code, const char* func, const char* file, int line) {
  if (code >= 0 && code < MALELF_LAST_ERRNO) {
      LOG_ERROR("[%s][function %s][line %d][code %d] %s\n", file, func, line, code, strerror(code));
  } else if (code >= 0 && code < MALELF_LAST_ERROR) {
      LOG_ERROR("[%s][function %s][line %d][code %d] %s\n", file, func, line, code, malelf_strerror(code));
  } else {
    LOG_ERROR("[%s][function %s][line %d][code %d] %s\n", file, func, line, code, "UNKNOW ERROR");
  }
}
