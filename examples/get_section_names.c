/**
 * Simple example that show how to get a section and stores on MalelfSection
 * and how to simple obtain the section names by index.
 *
 * by i4k
 */

#include <stdio.h>
#include <assert.h>

#include <malelf/binary.h>
#include <malelf/error.h>

int main() 
{
	MalelfBinary bin;
	MalelfSection section;
	int error = MALELF_SUCCESS, i = 0;
	char *name = NULL;

	malelf_binary_init(&bin);

	error = malelf_binary_open("/bin/ls", &bin);
	if (MALELF_SUCCESS != error) {
		malelf_perror(error);
		return 1;
	}

	/* Getting the section properties */
	error = malelf_binary_get_section(1, &bin, &section);

	/* Getting only the section name */
	error = malelf_binary_get_section_name(1, &bin, &name);

	assert (section.name == name);

	printf("Section '%s'\n", section.name);
	printf("\tType: %u\n", section.type);
	printf("\toffset in file: 0x%08x\n", section.offset);
	printf("\tsize in file: %u\n\n", section.size);

	/* Getting only the name of sections */
	for (i = 0; i < MALELF_ELF_FIELD(&bin.ehdr, e_shnum, error); i++) {
		if (i == 0)
			continue;

		error = malelf_binary_get_section_name(i, &bin, &name);
		printf("Section name: %s\n", name);
	}

	malelf_binary_close(&bin);
	
	return 0;
}
