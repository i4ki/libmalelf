#ifndef __BINARY_TEST__
#define __BINARY_TEST__

#include "../src/include/malelf/defines.h"
#include "../src/include/malelf/binary.h"
#include "../src/include/malelf/types.h"
#include "../src/include/malelf/error.h"

#include <CUnit/Basic.h>

MALELF_BEGIN_DECLS

extern CU_ErrorCode binary_get_test_suite(CU_pSuite *rsuite);

MALELF_END_DECLS


#endif /* __BINARY_TEST__ */
