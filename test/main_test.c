/*
 * The libmalelf is an evil library that could be used for good! It was
 * developed with the intent to assist in the process of infecting
 * binaries and provide a safe way to analyze malwares.
 *
 * Evil using this library is the responsibility of the programmer.
 *
 * Author:
 *         Tiago Natel de Moura <natel@secplus.com.br>
 *
 * Contributors:
 *         Daniel Ricardo dos Santos <danielricardo.santos@gmail.com>
 *         Paulo Leonardo Benatto    <benatto@gmail.com>
 *
 * Copyright 2012, 2013 by Tiago Natel de Moura. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <stdio.h>
#include <stdlib.h>

#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

#include <malelf/defines.h>

CU_ErrorCode binary_get_test_suite(CU_pSuite *rsuite);
CU_ErrorCode ehdr_get_test_suite(CU_pSuite *rsuite);
CU_ErrorCode report_get_test_suite(CU_pSuite *rsuite);
CU_ErrorCode debug_get_test_suite(CU_pSuite *rsuite);
CU_ErrorCode util_get_test_suite(CU_pSuite *rsuite);
CU_ErrorCode infect_get_test_suite(CU_pSuite *rsuite);

int main()
{
   CU_pSuite binary_suite = NULL;
   CU_pSuite ehdr_suite = NULL;
   CU_pSuite report_suite = NULL;
   CU_pSuite debug_suite = NULL;
   CU_pSuite util_suite = NULL;
   CU_pSuite infect_suite = NULL;

   /* initialize the CUnit test registry */
   if (CUE_SUCCESS != CU_initialize_registry()) {
      return CU_get_error();
   }

   /* add a suite to the registry */
   if (CUE_SUCCESS != ehdr_get_test_suite(&ehdr_suite) ||
       CUE_SUCCESS != report_get_test_suite(&report_suite) ||
       CUE_SUCCESS != debug_get_test_suite(&debug_suite) ||
       CUE_SUCCESS != util_get_test_suite(&util_suite) ||
       CUE_SUCCESS != binary_get_test_suite(&binary_suite) ||
       CUE_SUCCESS != infect_get_test_suite(&infect_suite)) {
           fprintf(stderr, "Failed to create test suite.\n");
           CU_cleanup_registry();
           return 1;
   }

   /* Run all tests using the CUnit Basic interface */
   CU_basic_set_mode(CU_BRM_VERBOSE);
   CU_basic_run_tests();
   CU_cleanup_registry();
   return CU_get_error();
}
