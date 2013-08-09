/*
 * The libmalelf is a evil library that could be used for good ! It was
 * developed with the intent to assist in the process of infecting
 * binaries and provide a safe way to analyze malwares.
 *
 * Evil using this library is the responsibility of the programmer.
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
#include <malelf/types.h>

#define MALELF_DEBUG_OUTPUT (stderr)
#define STRINGFY(x) #x
#define TOSTRING(x) STRINGFY(x)

#define MALELF_DEBUG_LOG_NONE (0)
#define MALELF_DEBUG_LOG_INFO (1)
#define MALELF_DEBUG_LOG_WARN (2)
#define MALELF_DEBUG_LOG_ERROR (3)
#define MALELF_DEBUG_LOG_CRITICAL (4)

#define _MALELF_DEBUG_TEST(code, ...)                           \
        __malelf_debug(code,                                    \
                       __FUNCTION__,                            \
                       __FILE__,                                \
                       TOSTRING(__LINE__),                      \
                       __VA_ARGS__)

#define _MALELF_DEBUG(code, ...)                                \
        do {                                                    \
                if (_malelf_debug >= code &&                    \
                    _malelf_debug <= MALELF_DEBUG_LOG_CRITICAL) {     \
                        _MALELF_DEBUG_TEST(code, __VA_ARGS__);  \
                }                                               \
        } while(0)

#define MALELF_DEBUG_INFO(...) _MALELF_DEBUG(MALELF_DEBUG_LOG_INFO,\
                                             __VA_ARGS__)
#define MALELF_DEBUG_WARN(...) _MALELF_DEBUG(MALELF_DEBUG_LOG_WARN,\
                                             __VA_ARGS__)
#define MALELF_DEBUG_ERROR(...) _MALELF_DEBUG(MALELF_DEBUG_LOG_ERROR, \
                                              __VA_ARGS__)
#define MALELF_DEBUG_CRITICAL(...) _MALELF_DEBUG(MALELF_DEBUG_LOG_CRITICAL,   \
                                                 __VA_ARGS__)
#define MALELF_DEBUG MALELF_DEBUG_INFO

#define MALELF_DEBUG_TEST_WARN(...)                             \
        _MALELF_DEBUG_TEST(MALELF_DEBUG_LOG_INFO, __VA_ARGS__)
#define MALELF_DEBUG_TEST_INFO(...)                             \
        _MALELF_DEBUG_TEST(MALELF_DEBUG_LOG_WARN, __VA_ARGS__)
#define MALELF_DEBUG_TEST_ERROR(...)                            \
        _MALELF_DEBUG_TEST(MALELF_DEBUG_LOG_ERROR, __VA_ARGS__)
#define MALELF_DEBUG_TEST_CRITICAL(...)                         \
        _MALELF_DEBUG_TEST(MALELF_DEBUG_LOG_CRITICAL, __VA_ARGS__)
#define MALELF_DEBUG_TEST MALELF_DEBUG_TEST_INFO

extern _u8 _malelf_debug;
extern _u8 _malelf_debug_ok;
extern FILE *_malelf_debug_fd;

extern void malelf_debug_init();
extern void malelf_debug_cleanup();
extern int __malelf_debug(_u8 logcode,
                          const char *func,
                          const char *file,
                          const char *line,
                          const char * fmt,
                          ...);
