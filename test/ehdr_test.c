#include <stdio.h>
#include <stdlib.h>

#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

#include "ehdr_test.h"
#include "binary_test.h"

static void malelf_ehdr_TEST(void)
{
        MalelfBinary bin;
        MalelfEhdr ehdr;
        _i32 result;

        malelf_binary_init(&bin);
        result = malelf_binary_open("bintest/uninfected", &bin);
        CU_ASSERT(result == MALELF_SUCCESS);

        result = malelf_binary_get_ehdr(&bin, &ehdr);
        CU_ASSERT(result == MALELF_SUCCESS);
        CU_ASSERT(NULL != ehdr.h32);

        _u8 class;
        result = malelf_binary_get_class(&bin, &class);
        CU_ASSERT(result == MALELF_SUCCESS);
        CU_ASSERT(class == MALELF_ELF32 || class == MALELF_ELF64);

        MalelfEhdrType me_type;
        result = malelf_ehdr_get_type(&ehdr, class, &me_type);
        CU_ASSERT(result == MALELF_SUCCESS);

        MalelfEhdrVersion me_version;
        result = malelf_ehdr_get_version(&ehdr, class, &me_version);
        CU_ASSERT(result == MALELF_SUCCESS);
        
        MalelfEhdrMachine me_machine;
        result = malelf_ehdr_get_machine(&ehdr, class, &me_machine);
        CU_ASSERT(result == MALELF_SUCCESS);

        _u32 shoff;
        result = malelf_ehdr_get_shoff(&ehdr, class, &shoff);
        CU_ASSERT(result == MALELF_SUCCESS);
        
        _u32 phoff;
        result = malelf_ehdr_get_phoff(&ehdr, class, &phoff);
        CU_ASSERT(result == MALELF_SUCCESS);
        
        _u32 entry;
        result = malelf_ehdr_get_phoff(&ehdr, class, &entry);
        CU_ASSERT(result == MALELF_SUCCESS);

        _u32 ehsize;
        result =  malelf_ehdr_get_ehsize(&ehdr, class, &ehsize);
        CU_ASSERT(result == MALELF_SUCCESS);
        
        _u32 phentsize;  
        result = malelf_ehdr_get_phentsize(&ehdr, class, &phentsize);
        CU_ASSERT(result == MALELF_SUCCESS);

        _u32 phnum;
        result = malelf_ehdr_get_phnum(&ehdr, class, &phnum);
        CU_ASSERT(result == MALELF_SUCCESS);

        _u32 shnum;
        result = malelf_ehdr_get_shnum(&ehdr, class, &shnum);
        CU_ASSERT(result == MALELF_SUCCESS);
        
        _u32 shentsize;
        result = malelf_ehdr_get_shentsize(&ehdr, class, &shentsize);
        CU_ASSERT(result == MALELF_SUCCESS);

        _u32 shstrndx;
        result = malelf_ehdr_get_shstrndx(&ehdr, class, &shstrndx);
        CU_ASSERT(result == MALELF_SUCCESS);

        _u32 flags;
        result = malelf_ehdr_get_flags(&ehdr, class, &flags);
        CU_ASSERT(result == MALELF_SUCCESS);
}

CU_ErrorCode ehdr_get_test_suite(CU_pSuite *rsuite)
{
	CU_pSuite suite = NULL;

	if (NULL == rsuite) {
		return -1;
	}

	suite = CU_add_suite("Class Ehdr", NULL, NULL);
	if(NULL == suite) {
		*rsuite = NULL;
		return CU_get_error();
	}

	if (NULL == CU_add_test(suite, 
                                "malelf_ehdr_TEST", 
                                malelf_ehdr_TEST)) {
	        *rsuite = NULL;
	        return CU_get_error();
	}

        *rsuite = suite;
        return CUE_SUCCESS;
}
