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

#include <malelf/error.h>
#include <malelf/binary.h>

#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

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
        CU_ASSERT(NULL != ehdr.uhdr.h32);

        CU_ASSERT(result == MALELF_SUCCESS);
        CU_ASSERT(ehdr.class == MALELF_ELF32 || ehdr.class == MALELF_ELF64);

        MalelfEhdrTable me_type;
        result = malelf_ehdr_get_type(&ehdr, &me_type);
        CU_ASSERT(result == MALELF_SUCCESS);

        MalelfEhdrTable me_version;
        result = malelf_ehdr_get_version(&ehdr, &me_version);
        CU_ASSERT(result == MALELF_SUCCESS);

        MalelfEhdrTable me_machine;
        result = malelf_ehdr_get_machine(&ehdr, &me_machine);
        CU_ASSERT(result == MALELF_SUCCESS);

        _u32 shoff;
        result = malelf_ehdr_get_shoff(&ehdr, &shoff);
        CU_ASSERT(result == MALELF_SUCCESS);

        _u32 phoff;
        result = malelf_ehdr_get_phoff(&ehdr, &phoff);
        CU_ASSERT(result == MALELF_SUCCESS);

        _u32 entry;
        result = malelf_ehdr_get_phoff(&ehdr, &entry);
        CU_ASSERT(result == MALELF_SUCCESS);

        _u32 ehsize;
        result =  malelf_ehdr_get_ehsize(&ehdr, &ehsize);
        CU_ASSERT(result == MALELF_SUCCESS);

        _u32 phentsize;
        result = malelf_ehdr_get_phentsize(&ehdr, &phentsize);
        CU_ASSERT(result == MALELF_SUCCESS);

        _u32 phnum;
        result = malelf_ehdr_get_phnum(&ehdr, &phnum);
        CU_ASSERT(result == MALELF_SUCCESS);

        _u32 shnum;
        result = malelf_ehdr_get_shnum(&ehdr, &shnum);
        CU_ASSERT(result == MALELF_SUCCESS);

        _u32 shentsize;
        result = malelf_ehdr_get_shentsize(&ehdr, &shentsize);
        CU_ASSERT(result == MALELF_SUCCESS);

        _u32 shstrndx;
        result = malelf_ehdr_get_shstrndx(&ehdr, &shstrndx);
        CU_ASSERT(result == MALELF_SUCCESS);

        _u32 flags;
        result = malelf_ehdr_get_flags(&ehdr, &flags);
        CU_ASSERT(result == MALELF_SUCCESS);
}

CU_ErrorCode ehdr_get_test_suite(CU_pSuite *rsuite)
{
        CU_pSuite suite = NULL;

        if (NULL == rsuite) {
                return -1;
        }

        suite = CU_add_suite("Module Ehdr", NULL, NULL);
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
