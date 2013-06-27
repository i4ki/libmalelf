/**
 * Simple example that shows how to get the informations of EHDR
 * using the libmalelf API.
 *
 * by patito
 */

#include <stdio.h>
#include <malelf/binary.h>
#include <malelf/ehdr.h>
#include <malelf/shdr.h>
#include <malelf/phdr.h>
#include <malelf/defines.h>
#include <malelf/disas.h>


int main()
{
        MalelfBinary binary;
        MalelfDisas disas;

        malelf_binary_init(&binary);
        malelf_binary_open(&binary, "/bin/ls");

        malelf_disas_init(&disas, &binary);

        malelf_disas(&disas);


        malelf_binary_close(&binary);

        return 0;
}
