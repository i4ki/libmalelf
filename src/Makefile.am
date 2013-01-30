CFLAGS_LANGUAGE=-std=c99 -pedantic
CFLAGS_WARNS=-Wall -Wextra -Werror
CFLAGS_INCLUDES=-Iinclude

AM_CFLAGS=	-ggdb -fPIC -O2 $(CFLAGS_LANGUAGE) \
		$(CFLAGS_WARNS) \
		$(CFLAGS_INCLUDES)

lib_LTLIBRARIES=libmalelf.la

libmalelf_la_SOURCES =  binary.c \
			ehdr.c \
			phdr.c \
			shdr.c \
			error.c \
			util.c \
			shellcode.c


libmalelf_la_LDFLAGS = -version-info 1:0:0
libmalelf_la_LIBADD=

library_includedir=$(includedir)/malelf
library_include_HEADERS	=	include/malelf/binary.h \
				include/malelf/ehdr.h \
				include/malelf/phdr.h \
				include/malelf/shdr.h \
				include/malelf/defines.h \
				include/malelf/error.h \
				include/malelf/types.h \
				include/malelf/util.h \
				include/malelf/shellcode.h
