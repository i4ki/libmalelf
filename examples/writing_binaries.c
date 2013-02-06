#include <stdio.h>

#include <malelf/binary.h>
#include <malelf/error.h>

int main(int argc, char **argv) {
	char *ifname, *ofname;
	unsigned new_entry;
	MalelfBinary bin;
	MalelfEhdr ehdr;
	int error;

	if (argc < 4) {
		printf("Usage: %s <input-binary> "
		       "<output-binary> <new-entry_point in decimal>\n", *argv);
		return 1;
	}

	ifname = argv[1];
	ofname = argv[2];
	new_entry = atoi(argv[3]);

	malelf_binary_init(&bin);
	error = malelf_binary_open(ifname, &bin);
	if (MALELF_SUCCESS != error) {
		malelf_perror(error);
		return 1;
	}

	error = malelf_binary_get_ehdr(&bin, &ehdr);
	if (MALELF_SUCCESS != error) {
		malelf_perror(error);
		return 1;
	}

	error = malelf_ehdr_set_entry(&ehdr, new_entry);
	if (MALELF_SUCCESS != error) {
		malelf_perror(error);
		return 1;
		}

	error = malelf_binary_write(&bin, ofname);
	if (MALELF_SUCCESS != error) {
		malelf_perror(error);
		return 1;
	}

	malelf_binary_close(&bin);
	
	return 0;
}
