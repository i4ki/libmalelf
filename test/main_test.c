#include <stdio.h>
#include <stdlib.h>

#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

#include "binary_test.h"
#include "ehdr_test.h"

#include "../src/include/malelf/defines.h"

int main()
{
   CU_pSuite binary_suite = NULL;
   CU_pSuite ehdr_suite = NULL;

   /* initialize the CUnit test registry */
   if (CUE_SUCCESS != CU_initialize_registry()) {
      return CU_get_error();
   }

   /* add a suite to the registry */
   if (CUE_SUCCESS != binary_get_test_suite(&binary_suite) ||
       CUE_SUCCESS != ehdr_get_test_suite(&ehdr_suite)) {
	CU_cleanup_registry();
   }

   /* Run all tests using the CUnit Basic interface */
   CU_basic_set_mode(CU_BRM_VERBOSE);
   CU_basic_run_tests();
   CU_cleanup_registry();
   return CU_get_error();
}
