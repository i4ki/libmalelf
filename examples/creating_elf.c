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

int main(int argc, char **argv)
{
        MalelfBinary bin;
        Elf32_Phdr phdr_load, phdr_note, phdr_phdr;
        _u32 error;
        int fd;
        struct stat st_info;
        unsigned char *text_data;

        if (argc < 2) {
                printf("%s <text-segment-file> <output-elf>\n", *argv);
                return 1;
        }

        fd = open(argv[1], O_RDONLY);

        if (fd == -1) {
                fprintf(stderr, "Failed to open %s...\n", argv[1]);
                return 1;
        }

        if (stat(argv[1], &st_info) == -1) {
                perror("Failed to stat file.\n");
                return 1;
        }


        text_data = mmap(NULL, st_info.st_size, PROT_READ, MAP_SHARED, fd, 0);
        if (!text_data) {
                perror("Failed to mmap...\n");
                return 1;
        }

        malelf_binary_init(&bin);
        error = malelf_binary_create_elf_exec(&bin, MALELF_ELF32);

        if (MALELF_SUCCESS != error) {
                MALELF_PERROR(error);
                return 1;
        }

        phdr_phdr.p_type = PT_PHDR;
        phdr_phdr.p_offset = sizeof (Elf32_Ehdr);
        phdr_phdr.p_vaddr = MALELF_ORIGIN + phdr_phdr.p_offset;
        phdr_phdr.p_paddr = phdr_phdr.p_vaddr;
        phdr_phdr.p_flags = PF_R | PF_X;
        phdr_phdr.p_filesz = phdr_phdr.p_memsz = (sizeof (Elf32_Phdr) * 3) + phdr_phdr.p_offset;
        phdr_phdr.p_align = 0;

        error = malelf_binary_add_phdr32(&bin, &phdr_phdr);

        if (MALELF_SUCCESS != error) {
                MALELF_PERROR(error);
                malelf_binary_close(&bin);
                return 1;
        }

        /* First, configure your executable (PT_LOAD) segment */
        phdr_load.p_type = PT_LOAD;
        phdr_load.p_offset = sizeof (Elf32_Ehdr) + sizeof (Elf32_Phdr) * 3;
        phdr_load.p_vaddr = 0x08048000 + phdr_load.p_offset;
        phdr_load.p_paddr = phdr_load.p_vaddr;
        phdr_load.p_filesz = st_info.st_size;
        phdr_load.p_memsz = phdr_load.p_filesz;
        phdr_load.p_flags = PF_X | PF_R;
        phdr_load.p_align = 0;

        error = malelf_binary_add_phdr32(&bin, &phdr_load);

        if (MALELF_SUCCESS != error) {
                MALELF_PERROR(error);
                malelf_binary_close(&bin);
                return 1;
        }

        /* content of NOTE segment */
        const char * message = "generated libmalelf";

        phdr_note.p_type = PT_NOTE;
        phdr_note.p_offset = phdr_load.p_offset + st_info.st_size;
        phdr_note.p_vaddr = 0x08048000 + phdr_load.p_offset + st_info.st_size;
        phdr_note.p_paddr = phdr_note.p_vaddr;
        phdr_note.p_filesz = strlen(message);
        phdr_note.p_memsz = phdr_note.p_filesz;
        phdr_note.p_flags = PF_R | PF_W;
        phdr_note.p_align = 0;

        error = malelf_binary_add_phdr32(&bin, &phdr_note);

        if (MALELF_SUCCESS != error) {
                MALELF_PERROR(error);
                malelf_binary_close(&bin);
                return 1;
        }

        /* copying text segment */
        bin.mem = malelf_realloc(bin.mem, phdr_load.p_offset + st_info.st_size);
        memcpy(bin.mem + phdr_load.p_offset, text_data, st_info.st_size);

        /* copying note segment */
        bin.mem = malelf_realloc(bin.mem, phdr_note.p_offset + phdr_note.p_filesz);
        memcpy(bin.mem + phdr_note.p_offset, message, phdr_note.p_filesz);

        malelf_ehdr_set_entry(&bin.ehdr, phdr_load.p_vaddr);

        bin.size = phdr_note.p_offset + phdr_note.p_filesz;

        error = malelf_binary_write(&bin, argv[2], 1);

        if (MALELF_SUCCESS != error) {
                MALELF_PERROR(error);
                return 1;
        }

        munmap(text_data, st_info.st_size);
        malelf_binary_close(&bin);
        return 0;
}
