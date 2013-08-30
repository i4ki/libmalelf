#include <stdint.h>
#include <elf.h>

main()
{
    union {
        Elf32_Ehdr *ehdr;
        uint32_t *p;
    } a;
    a.p = (uint32_t*)((uint32_t)main & ~4095);
    while (*a.p != 0x464c457f) {
            printf("addr: 0x%08x\n", a.p);
            a.p -= 1024;
    }
    printf("Pointer 0x%08x, My entry point is %08x\n", a.p, a.ehdr->e_entry);

}
