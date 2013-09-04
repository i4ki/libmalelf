#include <stdio.h>

#include <malelf/binary.h>
#include <malelf/shellcode.h>
#include <malelf/error.h>

int main(int argc, char **argv)
{
        MalelfBinary in, out;
        _u8 error;
        _u32 magic_offset = 0;
        /* original entry and default magic number */
        unsigned long int original_entry_point = 0;
        unsigned long int magic_number = 0x37333331;

        if (argc < 3) {
                fprintf(stdout, "usage: %s <in> <out> [,<original-entry>]", *argv);
                return 1;
        }

        if (argc > 3) {
                original_entry_point = atoi(argv[3]);
        }

        malelf_binary_init(&in);
        malelf_binary_init(&out);

        in.class = MALELF_FLAT;
        out.class = MALELF_FLAT;
        error = malelf_binary_open(&in, argv[1]);
        if (MALELF_SUCCESS != error) {
                MALELF_PERROR(error);
                return 1;
        }

        error = malelf_shellcode_create_flat(&out,
                                             &in,
                                             &magic_offset,
                                             original_entry_point,
                                             magic_number);

        if (MALELF_SUCCESS != error) {
                MALELF_PERROR(error);
                return 1;
        }

        printf("Return point added at offset '%u' of payload.\n",
               magic_offset);

        error = malelf_binary_write(&out, argv[2], 1);
        if (MALELF_SUCCESS != error) {
                MALELF_PERROR(error);
                return 1;
        }

        malelf_binary_close(&in);
        malelf_binary_close(&out);

        return 0;
}
