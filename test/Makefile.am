SUBDIRS = bintest

TESTS = main_test

check_PROGRAMS = main_test

bin_PROGRAMS = main_test

AM_CFLAGS = 	-Wall -Werror -ggdb \
		-I../src/include

LDADD=-L../src/.libs -lmalelf -lcunit

main_test_SOURCES = 	ehdr_test.c \
			binary_test.c \
			debug_test.c \
			util_test.c \
			report_test.c \
			main_test.c
