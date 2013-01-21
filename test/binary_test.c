#include <stdio.h>
#include <stdlib.h>

#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

#include "binary_test.h"

static void malelf_binary_open_mmap_TEST(void)
{
       MalelfBinary bin;
       _i32 result;

       malelf_binary_init(&bin);

       result = malelf_binary_open("test/uninfected", &bin);
       CU_ASSERT(result == MALELF_SUCCESS);
       result = malelf_binary_close(&bin);
       CU_ASSERT(result == MALELF_SUCCESS);

       malelf_binary_init(&bin);
       
       result = malelf_binary_open("/wrong/path/uninfected", &bin);
       CU_ASSERT(result == MALELF_ENOENT);
       result = malelf_binary_close(&bin);
       CU_ASSERT(result == MALELF_SUCCESS);
}

static void malelf_binary_open_malloc_TEST(void)
{
       MalelfBinary bin;
       _i32 result;

       malelf_binary_init(&bin);
       malelf_binary_set_alloc_type(&bin, MALELF_ALLOC_MALLOC);

       result = malelf_binary_open("test/uninfected", &bin);
       CU_ASSERT(result == MALELF_SUCCESS);
       result = malelf_binary_close(&bin);
       CU_ASSERT(result == MALELF_SUCCESS);

       malelf_binary_init(&bin);
       
       result = malelf_binary_open("/wrong/path/uninfected", &bin);
       CU_ASSERT(result == MALELF_ENOENT);
       result = malelf_binary_close(&bin);
       CU_ASSERT(result == MALELF_SUCCESS);
}


CU_ErrorCode binary_get_test_suite(CU_pSuite *rsuite)
{
	CU_pSuite suite = NULL;

	if (NULL == rsuite) {
		return -1;
	}

	suite = CU_add_suite("Class Binary", NULL, NULL);
	if(NULL == suite) {
		*rsuite = NULL;
		return CU_get_error();
	}

	if ((NULL == CU_add_test(suite, 
                                "malelf_binary_open_mmap_TEST", 
                                malelf_binary_open_mmap_TEST)) ||
            (NULL == CU_add_test(suite,
                                "malelf_binary_open_malloc_TEST",
                                malelf_binary_open_malloc_TEST))) {
	        *rsuite = NULL;
	        return CU_get_error();
	}

        *rsuite = suite;
        return CUE_SUCCESS;
}
