#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/mman.h>
#include <elf.h>

#include <malelf/binary.h>
#include <malelf/error.h>
#include <malelf/util.h>

int main(int argc, char **argv) 
{
	MalelfBinary bin;
	Elf32_Phdr phdr;
	_u32 error;
	int fd;
	struct stat st_info;
	unsigned char *text_data;

	if (argc < 2) {
		printf("%s <text-segment-file>\n", *argv);
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
	error = malelf_binary_create_elf_exec32(&bin);
	
	if (MALELF_SUCCESS != error) {
		malelf_perror(error);
		return 1;
	}

	phdr.p_type = PT_LOAD;
	phdr.p_offset = sizeof (Elf32_Ehdr) + sizeof (Elf32_Phdr) * 2;
	phdr.p_vaddr = 0x08048000 + phdr.p_offset;
	phdr.p_paddr = phdr.p_vaddr;
	phdr.p_filesz = st_info.st_size;
	phdr.p_memsz = phdr.p_filesz;
	phdr.p_flags = PF_X;

	error = malelf_binary_add_phdr32(&bin, &phdr);

	if (MALELF_SUCCESS != error) {
		malelf_perror(error);
		malelf_binary_close(&bin);
		return 1;
	}

	bin.mem = malelf_realloc(bin.mem, phdr.p_offset + st_info.st_size);

	memcpy(bin.mem + phdr.p_offset, text_data, st_info.st_size);

	malelf_ehdr_set_entry(&bin.ehdr, phdr.p_vaddr);

	error = malelf_binary_write(&bin, "./new_elf");

	if (MALELF_SUCCESS != error) {
		malelf_perror(error);
		return 1;
	}

	munmap(text_data, st_info.st_size);
	malelf_binary_close(&bin);
	return 0;
}