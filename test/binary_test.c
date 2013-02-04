#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>


#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

#include "binary_test.h"

static void malelf_binary_open_mmap_TEST(void)
{
       MalelfBinary bin;
       _i32 result;

       malelf_binary_init(&bin);

       result = malelf_binary_open("bintest/uninfected", &bin);

       CU_ASSERT(result == MALELF_SUCCESS);
       CU_ASSERT(NULL != bin.fname);
       CU_ASSERT(bin.fd > 2);
       CU_ASSERT(NULL != bin.mem);
       CU_ASSERT(bin.size > 0);
       CU_ASSERT(NULL != bin.ehdr.uhdr.h32);
       CU_ASSERT(NULL != &bin.phdr.uhdr.h32);
       CU_ASSERT(NULL != &bin.shdr.h32);
       CU_ASSERT(bin.alloc_type == MALELF_ALLOC_MMAP);
       CU_ASSERT(bin.class == MALELF_ELF32 ||
                 bin.class == MALELF_ELF64);
       result = malelf_binary_close(&bin);

       CU_ASSERT(result == MALELF_SUCCESS);
       CU_ASSERT(NULL == bin.fname);
       CU_ASSERT(bin.fd == -1);
       CU_ASSERT(NULL == bin.mem);
       CU_ASSERT(bin.size == 0);
       CU_ASSERT(NULL == bin.ehdr.uhdr.h32);
       CU_ASSERT(NULL == bin.phdr.uhdr.h32);
       CU_ASSERT(NULL == bin.shdr.h32);
       CU_ASSERT(bin.alloc_type == MALELF_ALLOC_NONE);
       CU_ASSERT(bin.class == MALELF_ELFNONE);
       
       malelf_binary_init(&bin);

       /* Should fail */
       result = malelf_binary_open("/wrong/path/uninfected", &bin);
       CU_ASSERT(result == MALELF_ENOENT);
       CU_ASSERT(NULL == bin.fname);
       CU_ASSERT(bin.fd == -1);
       CU_ASSERT(NULL == bin.mem);
       CU_ASSERT(bin.size == 0);
       CU_ASSERT(NULL == bin.ehdr.uhdr.h32);
       CU_ASSERT(NULL == bin.phdr.uhdr.h32);
       CU_ASSERT(NULL == bin.shdr.h32);
       CU_ASSERT(bin.alloc_type == MALELF_ALLOC_MMAP);
       CU_ASSERT(bin.class == MALELF_ELFNONE);
       
       result = malelf_binary_close(&bin);

       /* munmap on a non allocated memory area. */
       CU_ASSERT(result == MALELF_EINVAL);
}

static void malelf_binary_open_malloc_TEST(void)
{
       MalelfBinary bin;
       _i32 result;

       malelf_binary_init(&bin);
       malelf_binary_set_alloc_type(&bin, MALELF_ALLOC_MALLOC);

       result = malelf_binary_open("bintest/uninfected", &bin);
       CU_ASSERT(result == MALELF_SUCCESS);
       CU_ASSERT(NULL != bin.fname);
       CU_ASSERT(bin.fd > 2);
       CU_ASSERT(NULL != bin.mem);
       CU_ASSERT(bin.size > 0);
       CU_ASSERT(NULL != bin.ehdr.uhdr.h32);
       CU_ASSERT(NULL != bin.phdr.uhdr.h32);
       CU_ASSERT(NULL != bin.shdr.h32);
       CU_ASSERT(bin.alloc_type == MALELF_ALLOC_MALLOC);
       CU_ASSERT(bin.class == MALELF_ELF32 ||
                 bin.class == MALELF_ELF64);
       
       result = malelf_binary_close(&bin);
       CU_ASSERT(result == MALELF_SUCCESS);

       malelf_binary_init(&bin);
       malelf_binary_set_alloc_type(&bin, MALELF_ALLOC_MALLOC);
       
       result = malelf_binary_open("/wrong/path/uninfected", &bin);
       CU_ASSERT(result == MALELF_ENOENT);
       CU_ASSERT(NULL == bin.fname);
       CU_ASSERT(bin.fd == -1);
       CU_ASSERT(NULL == bin.mem);
       CU_ASSERT(bin.size == 0);
       CU_ASSERT(NULL == bin.ehdr.uhdr.h32);
       CU_ASSERT(NULL == bin.phdr.uhdr.h32);
       CU_ASSERT(NULL == bin.shdr.h32);
       CU_ASSERT(bin.alloc_type == MALELF_ALLOC_MALLOC);
       CU_ASSERT(bin.class == MALELF_ELFNONE);

       result = malelf_binary_close(&bin);
       CU_ASSERT(result == MALELF_SUCCESS);

       CU_ASSERT(NULL == bin.fname);
       CU_ASSERT(bin.fd == -1);
       CU_ASSERT(NULL == bin.mem);
       CU_ASSERT(bin.size == 0);
       CU_ASSERT(NULL == bin.ehdr.uhdr.h32);
       CU_ASSERT(NULL == bin.phdr.uhdr.h32);
       CU_ASSERT(NULL == bin.shdr.h32);
       CU_ASSERT(bin.alloc_type == MALELF_ALLOC_NONE);
       CU_ASSERT(bin.class == MALELF_ELFNONE);
}

static void malelf_binary_get_section_name_TEST()
{
       MalelfBinary bin;
       _i32 result;
       char *name = NULL;

       malelf_binary_init(&bin);

       result = malelf_binary_open("bintest/uninfected", &bin);

       CU_ASSERT(result == MALELF_SUCCESS);
       CU_ASSERT(NULL != bin.fname);

       result = malelf_binary_get_section_name(1, &bin, &name);
       CU_ASSERT(MALELF_SUCCESS == result);

       CU_ASSERT_STRING_EQUAL(".interp", name);

       result = malelf_binary_get_section_name(2, &bin, &name);
       CU_ASSERT(MALELF_SUCCESS == result);
       CU_ASSERT_STRING_EQUAL(".note.ABI-tag", name);

       result = malelf_binary_get_section_name(12, &bin, &name);
       CU_ASSERT(MALELF_SUCCESS == result);
       CU_ASSERT_STRING_EQUAL(".init", name);	

       malelf_binary_close(&bin);
}

static void malelf_binary_get_section_TEST()
{
       MalelfBinary bin;
       _i32 result;
       MalelfSection section;

       malelf_binary_init(&bin);

       result = malelf_binary_open("bintest/uninfected", &bin);

       CU_ASSERT(result == MALELF_SUCCESS);
       CU_ASSERT(NULL != bin.fname);

       result = malelf_binary_get_section(1, &bin, &section);
       CU_ASSERT(MALELF_SUCCESS == result);
       CU_ASSERT_STRING_EQUAL(section.name, ".interp");
       CU_ASSERT(section.offset == 0x134);
       CU_ASSERT(section.size == 0x13);
       CU_ASSERT(section.shdr != NULL);

       result = malelf_binary_get_section(2, &bin, &section);
       CU_ASSERT(MALELF_SUCCESS == result);
       CU_ASSERT_STRING_EQUAL(section.name, ".note.ABI-tag");
       CU_ASSERT(section.offset == 0x148);
       CU_ASSERT(section.size == 0x20);
       CU_ASSERT(section.shdr != NULL);

       result = malelf_binary_get_section(14, &bin, &section);
       CU_ASSERT(MALELF_SUCCESS == result);
       CU_ASSERT_STRING_EQUAL(section.name, ".text");
       CU_ASSERT(section.offset == 0x320);
       CU_ASSERT(section.size == 0x170);
       CU_ASSERT(section.shdr != NULL);

       malelf_binary_close(&bin);
}

void malelf_binary_write_TEST()
{
	int error = MALELF_SUCCESS;
	MalelfBinary bin;
	struct stat st_info;

	malelf_binary_init(&bin);

	error = malelf_binary_open("bintest/uninfected", &bin);
	CU_ASSERT(MALELF_SUCCESS == error);
	malelf_perror(error);

	error = malelf_binary_write(&bin, "bintest/uninfected_copy");
	CU_ASSERT(MALELF_SUCCESS == error);
	
	CU_ASSERT(0 == stat("bintest/uninfected_copy", &st_info));
	CU_ASSERT(st_info.st_size > 0);
	CU_ASSERT(st_info.st_size == bin.size);

	malelf_binary_close(&bin);
//	unlink("bintest/uninfected_copy");
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
				 malelf_binary_open_malloc_TEST)) ||
	    (NULL == CU_add_test(suite, 
                                "malelf_binary_get_section_name_TEST", 
                                malelf_binary_get_section_name_TEST)) ||
            (NULL == CU_add_test(suite, 
                                "malelf_binary_get_section_TEST", 
                                malelf_binary_get_section_TEST)) ||
            (NULL == CU_add_test(suite, 
                                "malelf_binary_write_TEST", 
                                malelf_binary_write_TEST))) {
	        *rsuite = NULL;
	        return CU_get_error();
	}

        *rsuite = suite;
        return CUE_SUCCESS;
}
