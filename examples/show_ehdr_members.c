#include <stdio.h>
#include <malelf/binary.h>
#include <malelf/ehdr.h>
#include <malelf/shdr.h>
#include <malelf/phdr.h>
#include <malelf/defines.h>


int main()
{
        MalelfBinary binary;
        MalelfEhdr ehdr;
        MalelfEhdrType me_type;
        MalelfEhdrMachine me_machine;
        MalelfEhdrVersion me_version;

        _u8 class;
        _i32 result;
        _u32 size;
        _u32 phentsize;
        _u32 shentsize;
        _u32 phnum;
        _u32 shnum;
        _u32 shstrndx;
        UNUSED(result);

        malelf_binary_init(&binary);
        malelf_binary_set_alloc_type(&binary, MALELF_ALLOC_MALLOC);
    	malelf_binary_open("/bin/ls", &binary);
 
        result = malelf_binary_get_ehdr(&binary, &ehdr);
        result = malelf_binary_get_class(&binary, &class);
        result = malelf_ehdr_get_version(&ehdr, class, &me_version);        
        result = malelf_ehdr_get_type(&ehdr, class, &me_type);        
        result = malelf_ehdr_get_machine(&ehdr, class, &me_machine);        
        result = malelf_ehdr_get_ehsize(&ehdr, class, &size);        
        result = malelf_ehdr_get_phentsize(&ehdr, class, &phentsize);        
        result = malelf_ehdr_get_shentsize(&ehdr, class, &shentsize);        
        result = malelf_ehdr_get_shnum(&ehdr, class, &shnum);        
        result = malelf_ehdr_get_phnum(&ehdr, class, &phnum);        
        result = malelf_ehdr_get_shstrndx(&ehdr, class, &shstrndx);        

        printf("Version Name: %d\n", me_version.name);        
        printf("Version Value: %d\n", me_version.value);        
        printf("Version Description: %s\n", me_version.meaning);        

        printf("Type Name: %d\n", me_type.name);        
        printf("Type Value: %d\n", me_type.value);        
        printf("Type Description: %s\n", me_type.meaning);        

        printf("Machine Name: %d\n", me_machine.name);        
        printf("Machine Value: %d\n", me_machine.value);        
        printf("Machine Description: %s\n", me_machine.meaning);        
        
        printf("Size: %d\n", size);        
        printf("Program Header Table Entry Size: %d\n", phentsize);        
        printf("Section Header Table Entry Size: %d\n", shentsize);        
        
        printf("Number of Entries PHT: %d\n", phnum);        
        printf("Number of Entries SHT: %d\n", shnum);
        
        printf("SHT index: %d\n", shstrndx);
        
        malelf_binary_close(&binary);

        return 0;
}
