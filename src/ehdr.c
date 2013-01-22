#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <elf.h>

#include <malelf/types.h>
#include <malelf/error.h>
#include <malelf/ehdr.h>

_i32 malelf_ehdr_set(MalelfEhdr* ehdr, _u8 class, _u8 *mem, _u32 size) {
        assert(NULL != ehdr);
        assert(NULL != mem);
        
        switch (class) {
        case MALELF_ELF32:
                if (size > sizeof(Elf32_Ehdr)) {
                        return MALELF_EEHDR_OVERFLOW;
                }
                
                memcpy(ehdr->eh32, mem, size);
                break;
        case MALELF_ELF64:
                if (size > sizeof(Elf64_Ehdr)) {
                        return MALELF_EEHDR_OVERFLOW;
                }

                memcpy(ehdr->eh64, mem, size);
                break;
        default:
                return MALELF_EINVALID_CLASS;
        }

        return MALELF_SUCCESS;
}
