#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <limits.h>

#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>
#include <libgen.h>

#include <malelf/error.h>
#include <malelf/debug.h>
#include <malelf/binary.h>
#include <malelf/shellcode.h>
#include <malelf/infect.h>

#define TRUE 1
#define FALSE 0
#define PAGE_SIZE 4096

extern _u8 malelf_quiet_mode;

int init_suite_success(void) { return 0; }
int clean_suite_success(void) {
        /* unlink("/tmp/malelf-uninfected.out"); */
        /* unlink("/tmp/malelf-infected.out"); */
        return 0;
}

_i32 filestrcmp(char* file_path, char* str) {

        FILE* file = fopen(file_path, "r");
        char tmp[256]={0x0};

        while(file!=NULL && fgets(tmp, sizeof(tmp), file) != NULL)
        {
                if (strstr(tmp, str)){
                        fclose(file);
                        return 1;
                }
        }

        if(file != NULL) {
                fclose(file);
        }

        return 0;
}

_i32 filecmp(char* file1, char* file2) {
        MalelfBinary obj1, obj2;
        _i32 error;
        int i = 0;

        malelf_binary_init(&obj1);
        malelf_binary_init(&obj2);

        obj1.fname = file1;
        obj2.fname = file2;

        if ((error = malelf_binary_open(&obj1, file1))
            != MALELF_SUCCESS) {
                return error;
        }

        if ((error = malelf_binary_open(&obj2, file2))
            != MALELF_SUCCESS) {
                return error;
        }

        if (obj1.size == obj2.size) {
                for (i = 0; i < obj1.size; i++) {
                        if (obj1.mem[i] != obj2.mem[i]) {
                                error = MALELF_ERROR;
                                goto filecmp_exit;
                        }
                }
        } else {
                error = MALELF_ERROR;
                goto filecmp_exit;
        }

filecmp_exit:
        malelf_binary_close(&obj1);
        malelf_binary_close(&obj2);

        return error;
}

void test_malelf_infect_silvio_padding(char* malware_path,
                                       char* malware_message) {
        char* malware_path_gen = "/tmp/malware_ready.o";
        char* redir = " 2>&1 > ";
        char chmod_str[256];

        char* infected_dir = "infected/";
        char infected_path[256];
        char infected_exec[256];
        char infected_output_file[256];

        char* uninfected_dir = "hosts/";
        char uninfected_path[256];
        char uninfected_exec[256];
        char uninfected_output_file[256];

        unsigned long int magic_bytes = 0;
        int i;

        MalelfBinary input, output, malware, malware_in;
        _i32 error;

        char uninfected_files[][256] = {"/bin/echo",
                                        "/bin/ls",
                                        "/usr/bin/id",
                                        "/bin/ps",
                                        "/bin/pwd",
                                        "/bin/uname"
        };

        malelf_debug_init();

        memset(chmod_str, 0, 256);
        memset(infected_path, 0, 256);
        memset(infected_exec, 0, 256);
        memset(uninfected_path, 0, 256);
        memset(uninfected_exec, 0, 256);
        memset(infected_output_file, 0, 256);
        memset(uninfected_output_file, 0, 256);

        for (i = 0; i < sizeof(uninfected_files)/256; i++) {
                //Preparing strings for the tests
                strncpy(uninfected_path, uninfected_files[i], sizeof(uninfected_path) - 1);
                uninfected_path[sizeof(uninfected_path) - 1] = '\0';

                strncpy(infected_path, infected_dir, sizeof(infected_path) - 1);
                infected_path[sizeof(infected_path) - 1] = '\0';
                strncat(infected_path, basename(uninfected_path), sizeof(infected_path) - strlen(infected_path) - 1);

                strncpy(infected_output_file, infected_path, sizeof(infected_output_file) - 1);
                infected_output_file[sizeof(infected_output_file) - 1] = '\0';
                strncat(infected_output_file, ".out", sizeof(infected_output_file) - strlen(infected_output_file) - 1);

                strncpy(uninfected_output_file, uninfected_dir, sizeof(uninfected_output_file) - 1);
                uninfected_output_file[sizeof(uninfected_output_file) - 1] = '\0';
                strncat(uninfected_output_file, basename(uninfected_path), sizeof(uninfected_output_file) - strlen(uninfected_output_file) - 1);
                strncat(uninfected_output_file, ".out", sizeof(uninfected_output_file) - strlen(uninfected_output_file) - 1);

                strncpy(uninfected_exec, uninfected_path, sizeof(uninfected_exec) - 1);
                uninfected_exec[sizeof(uninfected_exec) - 1] = '\0';
                strncat(uninfected_exec, redir, sizeof(uninfected_exec) - strlen(uninfected_exec) - 1);
                strncat(uninfected_exec, uninfected_output_file, sizeof(uninfected_exec) - strlen(uninfected_exec) - 1);

                strncpy(infected_exec, "./", sizeof(infected_exec) - 1);
                infected_exec[sizeof(infected_exec) - 1] = '\0';
                strncat(infected_exec, infected_path, sizeof(infected_exec) - strlen(infected_exec) - 1);
                strncat(infected_exec, redir, sizeof(infected_exec) - strlen(infected_exec) - 1);
                strncat(infected_exec, infected_output_file, sizeof(infected_exec) - strlen(infected_exec) - 1);

                strncpy(chmod_str, "chmod +x ", sizeof(chmod_str) - 1);
                chmod_str[sizeof(chmod_str) - 1] = '\0';
                strncat(chmod_str, infected_path, sizeof(chmod_str) - strlen(chmod_str) - 1);

                malelf_binary_init(&input);
                malelf_binary_init(&output);
                malelf_binary_init(&malware);
                malelf_binary_init(&malware_in);

                //Preparing files for the tests
                input.fname = uninfected_path;
                output.fname = infected_path;

                error = malelf_binary_open(&input, uninfected_path);
                CU_ASSERT(MALELF_SUCCESS == error);

                malware.fname = malware_path_gen;
                if (input.class == MALELF_ELF32) {
                        malware.class = MALELF_FLAT32;
                } else {
                        malware.class = MALELF_FLAT64;
                }
                malware_in.class = malware.class;

                error = malelf_binary_open(&malware_in, malware_path);
                CU_ASSERT(MALELF_SUCCESS == error);

                if (MALELF_SUCCESS != error) {
                        MALELF_PERROR(error);
                        malelf_binary_close(&input);
                        return;
                }

                //Testing ...
                _u32 magic_offset = 0;
                error = malelf_shellcode_create_flat(&malware,
                                                     &malware_in,
                                                     &magic_offset,
                                                     0,
                                                     0);

                CU_ASSERT(error == MALELF_SUCCESS);

                //Testing ...
                if (input.class == MALELF_ELF32) {
                        error = malelf_infect_silvio_padding32(&input,
                                                               &output,
                                                               &malware,
                                                               0,
                                                               magic_bytes);
                } else {
                        error = malelf_infect_silvio_padding64(&input,
                                                               &output,
                                                               &malware,
                                                               0,
                                                               magic_bytes);
                }

                if (error != MALELF_SUCCESS) {
                        MALELF_PERROR(error);
                        return;
                }

                error = malelf_binary_write(&output, output.fname, 1);

                CU_ASSERT(MALELF_SUCCESS == error);
                if (MALELF_SUCCESS != error) {
                        MALELF_PERROR(error);
                        return;
                }

                malelf_binary_close(&input);
                malelf_binary_close(&output);
                malelf_binary_close(&malware_in);

                /* Testing ...*/
                error = system(chmod_str);
                CU_ASSERT(error == 0);

                /* Testing ... */
                error = system(uninfected_exec);
                CU_ASSERT((error != 134) && (error != 139) && (error != 4));

                /* Testing ... */
                error = system(infected_exec);
                CU_ASSERT((error != 134) && (error != 139) && (error != 4));

                /* Testing ... */
                error = filecmp(uninfected_output_file, infected_output_file);
                CU_ASSERT(error != 0);

                /* Testing ... */
                error = filestrcmp(infected_output_file, malware_message);
                CU_ASSERT(error != 0);
        }
}

void malelf_infect_silvio_padding_TEST(void)
{
        if ((int)(CHAR_BIT * sizeof(void *)) == 32) {
                test_malelf_infect_silvio_padding("malwares/write_message32.o", "OWNED BY I4K");
        } else {
                test_malelf_infect_silvio_padding("malwares/write_message64.o", "OWNED BY I4K");
        }
}

CU_ErrorCode infect_get_test_suite(CU_pSuite *rsuite)
{
        CU_pSuite suite = NULL;

        if (NULL == rsuite) {
                return -1;
        }

        suite = CU_add_suite("Class Infect", NULL, NULL);
        if(NULL == suite) {
                *rsuite = NULL;
                return CU_get_error();
        }

        if ((NULL == CU_add_test(suite,
                                 "malelf_infect_silvio_padding_TEST",
                                 malelf_infect_silvio_padding_TEST))) {
                *rsuite = NULL;
                return CU_get_error();
        }

        *rsuite = suite;
        return CUE_SUCCESS;
}
