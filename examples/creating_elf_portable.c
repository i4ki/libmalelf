/**
 * Simple example to create a RAW ELF Executable file.
 * Very useful if you need create a tiny ELF to send in a exploit or
 * simply to understand the ELF format.
 *
 * This example could be used to create a tiny ELF binary that execute
 * your shellcode/payload. This example contains a NOTE segment too for
 * demo of how to create more than one segment.
 *
 * ;; shellcode.asm
 *
 * BITS 32
 *
 * _start:
 *     push dword 0x37333331
 *     mov ecx, esp
 *     mov edx, 4
 *     mov ebx, 1
 *     mov eax, 4      ; write(stdout, "1337", 4)
 *     int 0x80
 *
 *     xor eax, eax
 *     xor ebx, ebx
 *     inc eax         ; exit(0)
 *     int 0x80
 *
 * ;; cut here ;;
 *
 * $ nasm -f bin ./shellcode.asm -o shellcode.bin
 *
 * $ ./creating_elf ./shellcode.bin ./tiny_elf
 * $ ./tiny_elf
 * 1337
 * $
 *
 * by i4k
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/mman.h>
#include <elf.h>

#include <malelf/defines.h>
#include <malelf/binary.h>
#include <malelf/error.h>
#include <malelf/util.h>

#if UINTPTR_MAX == 0xffffffff
/* 32-bit */
#define CURRENT_ARCH MALELF_ELF32
#elif UINTPTR_MAX == 0xffffffffffffffff
/* 64-bit */
#define CURRENT_ARCH MALELF_ELF64
#else
/* wtf */

#endif


int main(int argc, char **argv)
{
        MalelfBinary bin;
        MalelfBinary text_segment;
        MalelfPhdr uphdr_load, uphdr_note, uphdr_phdr;
        _u32 error;

        if (argc < 3) {
                fprintf(stderr,
                        "./creating_portable_elf <text-segment-file> <output>\n");
                return 0;
        }

        malelf_binary_init(&bin);
        malelf_binary_init(&text_segment);

        text_segment.class = MALELF_FLAT32;

        error = malelf_binary_open(&bin, argv[2]);
        if (MALELF_SUCCESS != error) {
                goto error_exit;
        }

        error = malelf_binary_open(&text_segment, argv[1]);
        if (MALELF_SUCCESS != error) {
                goto error_exit;
        }

        error = malelf_binary_create_elf_exec(&bin, CURRENT_ARCH);
        if (MALELF_SUCCESS != error) {
                goto error_exit;
        }

        /* set the class of PHDR based on your OS arch */
        malelf_phdr_set_class(&uphdr_phdr, CURRENT_ARCH);

        /* Create a PHDR of type PT_PHDR */
        malelf_phdr_set_type(&uphdr_phdr, PT_PHDR);

        /* Put the PT_PHDR after the EHDR */
        malelf_phdr_set_offset(&uphdr_phdr, MALELF_EHDR_SIZEOF(CURRENT_ARCH));

        /* Set the virtual address */
        malelf_phdr_set_vaddr(&uphdr_phdr,
                              MALELF_ORIGIN + MALELF_ELF_FIELD(&uphdr_phdr,
                                                               p_offset,
                                                               error));

        /* Set the physical address */
        malelf_phdr_set_paddr(&uphdr_phdr, MALELF_ELF_FIELD(&uphdr_phdr,
                                                            p_vaddr,
                                                            error));

        /* Set flags */
        malelf_phdr_set_flags(&uphdr_phdr, PF_R | PF_X);

        /* set the memory size of whole phdr */
        malelf_phdr_set_pmemz(&uphdr_phdr,
                              (MALELF_PHDR_SIZEOF(CURRENT_ARCH) * 3) +
                              MALELF_EHDR_SIZEOF(CURRENT_ARCH));

        /* set the file size of whole phdr */
        malelf_phdr_set_filesz(&uphdr_phdr,
                               (MALELF_PHDR_SIZEOF(CURRENT_ARCH) * 3) +
                               MALELF_EHDR_SIZEOF(CURRENT_ARCH));


        return 0;
}
