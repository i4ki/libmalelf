CFLAGS_LANGUAGE=-std=c99 -pedantic -D_POSIX_C_SOURCE \
		-D_DEFAULT_SOURCE
CFLAGS_WARNS=-Wall -Wextra -Werror
CFLAGS_INCLUDES=-Iinclude -I$(LIBXML_INCLUDES) -I$(LIBUDIS_INCLUDES)

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
			report.c \
			shellcode.c \
			table.c \
			debug.c \
			patch.c \
			disas.c \
			infect.c


libmalelf_la_LDFLAGS = -version-info 1:0:0
libmalelf_la_LIBADD=-L$(LIBXML_LIBPATH) -L$(LIBUDIS_LIBPATH) -lxml2 -ludis86

library_includedir=$(includedir)/malelf
library_include_HEADERS	=	include/malelf/binary.h \
				include/malelf/ehdr.h \
				include/malelf/phdr.h \
				include/malelf/shdr.h \
				include/malelf/report.h \
				include/malelf/defines.h \
				include/malelf/error.h \
				include/malelf/types.h \
				include/malelf/util.h \
				include/malelf/shellcode.h\
				include/malelf/table.h \
				include/malelf/debug.h 	\
				include/malelf/patch.h 	\
				include/malelf/disas.h 	\
				include/malelf/infect.h
