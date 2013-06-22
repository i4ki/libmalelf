/*
 * The libmalelf is a evil library that could be used for good ! It was
 * developed with the intent to assist in the process of infecting
 * binaries and provide a safe way to analyze malwares.
 *
 * Evil using this library is the responsibility of the programmer.
 *
 * Author:
 *         Tiago Natel de Moura <natel@secplus.com.br>
 *
 * Contributor:
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
#include <malelf/types.h>
#include <malelf/debug.h>
#include <malelf/util.h>
#include <malelf/error.h>

#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

void malelf_find_magic_number_TEST()
{
        _u32 error;
        _u32 offset_ret = 0;
        union malelf_dword magic;
        char *data1 = "1337hhfjkhdkshfkasdhfksdfhsdjfhksdhfksdhfksdhf"
                "dhfsdhf8ydsf897ydf89ydsf87sy8sdyf87dsyf87dsy87fsdy";

        magic.long_val = 0x37333331;

        error = malelf_find_magic_number((_u8 *)data1,
                                         strlen((char *)data1),
                                         magic,
                                         &offset_ret);

        CU_ASSERT(MALELF_SUCCESS == error);
        CU_ASSERT(offset_ret == 0);

        data1 = "013370";
        error = malelf_find_magic_number((_u8 *)data1,
                                         strlen(data1),
                                         magic,
                                         &offset_ret);
        CU_ASSERT(MALELF_SUCCESS == error);
        CU_ASSERT(offset_ret == 1);

        data1 = "\x00\x01\x0a\x05\x37\x33\x33\x33";
        error = malelf_find_magic_number((_u8 *)data1,
                                         8,
                                         magic,
                                         &offset_ret);
        CU_ASSERT(MALELF_ERROR == error);
        CU_ASSERT(offset_ret == 0);

        data1 = "\x00\x01\x0a\x05\x31\x33\x33\x37";
        error = malelf_find_magic_number((_u8 *)data1,
                                         8,
                                         magic,
                                         &offset_ret);
        CU_ASSERT(MALELF_SUCCESS == error);
        CU_ASSERT(offset_ret == 4);
}

CU_ErrorCode util_get_test_suite(CU_pSuite *rsuite)
{
        CU_pSuite suite = NULL;

        if (NULL == rsuite) {
                return -1;
        }

        suite = CU_add_suite("Module util", NULL, NULL);
        if(NULL == suite) {
                *rsuite = NULL;
                return CU_get_error();
        }

        if ((NULL == CU_add_test(suite,
                                 "malelf_find_magic_number_TEST",
                                 malelf_find_magic_number_TEST))) {
                *rsuite = NULL;
                return CU_get_error();
        }

        *rsuite = suite;
        return CUE_SUCCESS;
}
