#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <elf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

typedef uint8_t _u8;
typedef uint16_t _u16;
typedef uint32_t _u32;

typedef struct {
        union {
                Elf32_Ehdr *eh32;
                Elf64_Ehdr *eh64;
        };

        unsigned int class;
} malelfEhdrT;

typedef struct {
        Elf32_Ehdr ehdr;
        _u8 align[12];
        _u8 class;
} malelfEhdr32;

typedef struct {
        Elf64_Ehdr ehdr;
        _u8 class;
} malelfEhdr64;

#define MALELF_EHDRSZ sizeof(Elf64_Ehdr)
typedef struct {
        _u8 align[MALELF_EHDRSZ];
        _u8 class;
} malelfEhdr;

inline _u8 malelf_elf_ehdr_set(malelfEhdr *ehdr,_u8 *mem)
{
        assert(mem != NULL);

        if (mem[EI_CLASS] == ELFCLASS32) {
                malelfEhdr32 *eh32 = (malelfEhdr32 *) ehdr;
                memcpy(&eh32->ehdr, mem, sizeof(Elf32_Ehdr));
                eh32->class = ELFCLASS32;
                ehdr = (malelfEhdr *) eh32;
                printf("CLASS EQUALS TO '%u', from '%u'\n", ehdr->class, mem[EI_CLASS]);
                return 0;
        } else if (mem[EI_CLASS] == ELFCLASS64) {
                malelfEhdr64 *eh64 = (malelfEhdr64 *) ehdr;
                memcpy(&eh64->ehdr, mem, sizeof(Elf64_Ehdr));
                eh64->class = ELFCLASS64;
                ehdr = (malelfEhdr *) eh64;
                return 0;
        } else {
                fprintf(stderr, "UNKNOWN ELF CLASS\n");
                return 1;
        }
}

int main(int argc, char **argv) {
        int fd;
        _u8 *mem = NULL;
        malelfEhdr ehdr;
        struct stat st_info;

        if (argc < 2) {
                fprintf(stderr, "usage: %s <elf-binary>\n", *argv);
                return 0;
        }

        fd = open(argv[1], O_RDONLY);

        if (-1 == fd) {
                perror("Couldn't open(2) the file.\n");
                return 1;
        }

        if (-1 == fstat(fd, &st_info)) {
                perror("Couldn't fstat(2) the file.\n");
                return 2;
        }

        mem = mmap(0,
                   st_info.st_size,
                   PROT_READ|PROT_WRITE,
                   MAP_PRIVATE,
                   fd,
                   0);

        if (MAP_FAILED == mem) {
                perror("Couldn't mmap(2) the file.\n");
                return 3;
        }

        if (malelf_elf_ehdr_set(&ehdr, mem) == 0) {
                printf("[+] Binary successfully opened.\n");
                printf("[!] CLASS%s = %u\n", ehdr.class == ELFCLASS32 ?
                       "32" : ehdr.class == ELFCLASS64 ? "64" : "UNKNOWN",
                        ehdr.class);

                switch (ehdr.class) {
                case ELFCLASS32: {
                        malelfEhdr32 *eh32 = (malelfEhdr32 *) &ehdr;
                        printf("[!] entry point: %08x\n", eh32->ehdr.e_entry);
                        break;
                }
                case ELFCLASS64: {
                        malelfEhdr64 *eh64 = (malelfEhdr64 *) &ehdr;
                        printf("[!] entry point: %08x\n", eh64->ehdr.e_entry);
                        break;
                }
                default:
                        printf("Unknown ehdr...\n");
                }
                
        } else {
                fprintf(stderr, "[-] Failed to open binary file.\n");
                goto finish;
        }

        
finish:
        munmap(mem, st_info.st_size);
        
        return 0;
}
