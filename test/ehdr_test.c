#include <stdio.h>
#include <stdlib.h>

#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

#include "ehdr_test.h"
#include "binary_test.h"

static void malelf_ehdr_get_version_TEST(void)
{
        MalelfBinary bin;
        _i32 result;

        malelf_binary_init(&bin);
        result = malelf_binary_open("bintest/uninfected", &bin);
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
                                "malelf_ehdr_get_version_TEST", 
                                malelf_ehdr_get_version_TEST)) {
	        *rsuite = NULL;
	        return CU_get_error();
	}

        *rsuite = suite;
        return CUE_SUCCESS;
}
