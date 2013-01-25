#ifndef __EHDR_TEST__
#define __EHDR_TEST__

#include "../src/include/malelf/defines.h"
#include "../src/include/malelf/ehdr.h"
#include "../src/include/malelf/types.h"
#include "../src/include/malelf/error.h"

#include <CUnit/Basic.h>

MALELF_BEGIN_DECLS

extern CU_ErrorCode ehdr_get_test_suite(CU_pSuite *rsuite);

MALELF_END_DECLS


#endif /* __EHDR_TEST__ */
