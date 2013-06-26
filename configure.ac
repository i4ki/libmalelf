#AC_PREREQ([2.68])
AC_INIT([libmalelf], [1.0], [natel@secplus.com.br])

AC_MSG_RESULT([Welcome to AutoHELL])
AM_INIT_AUTOMAKE
AM_PROG_AS

dnl need libtool for libmalelf
LT_INIT
AC_CONFIG_SRCDIR([src/binary.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

HAVE_TESTS="yes"
dnl Enable unit-tests
AC_ARG_ENABLE([tests],
    AS_HELP_STRING([--enable-tests], [Enable Malelficus Unit Tests]))

AC_ARG_WITH([cunit-prefix],
            [AS_HELP_STRING([--with-cunit-prefix],
              [Use this CUnit prefix directory @<:@default=/usr@:>@])],
            [with_cunit_prefix="$withval"],
            [with_cunit_prefix=""])

if test "$with_cunit_prefix" != ""; then
   extra_includes="$extra_includes:$with_cunit_prefix/include"
fi

AC_ARG_WITH([libxml2-prefix],
	[AS_HELP_STRING([--with-libxml2-prefix],
	  [Use this libxml2 prefix directory @<:@default=/usr@:>])],
        [with_libxml2_prefix="$withval"],
	[with_libxml2_prefix=/usr])

with_libxml2_includes="$with_libxml2_prefix/include/libxml2"
with_libxml2_libpath="$with_libxml2_prefix/lib"

extra_includes="$extra_includes:$with_libxml2_prefix"
LIBXML_INCLUDES="$with_libxml2_includes"
LIBXML_LIBPATH="$with_libxml2_libpath"

AC_SUBST(LIBXML_INCLUDES)
AC_SUBST(LIBXML_LIBPATH)

AC_ARG_WITH([libudis-prefix],
	[AS_HELP_STRING([--with-libudis-prefix],
	  [Use this libudis86 prefix directory @<:@default=/usr/local@:>])],
        [with_libudis_prefix="$withval"],
	[with_libudis_prefix="/usr/local"])

with_libudis_includes="$with_libudis_prefix/include"
with_libudis_libpath="$with_libudis_prefix/lib"

extra_includes="$extra_includes:$with_libudis_prefix"
LIBUDIS_INCLUDES="$with_libudis_includes"
LIBUDIS_LIBPATH="$with_libudis_libpath"

AC_SUBST(LIBUDIS_INCLUDES)
AC_SUBST(LIBUDIS_LIBPATH)

AC_SUBST(extra_includes)

AS_IF([test "x$enable_tests" = "xyes"], [HAVE_TESTS=yes], [HAVE_TESTS=no])

# Checks for programs.
AC_PROG_CC
AC_CHECK_PROG([HAVE_NASM], [nasm], [true], [false])

# Checks for libraries.

CFLAGS_BK=$CFLAGS
CFLAGS="$CFLAGS -I$with_libxml2_includes"
CPPFLAGS_BK=$CPPFLAGS
CPPFLAGS="$CPPFLAGS -I$with_libxml2_includes"
# Checks for header files.
AC_CHECK_HEADERS([  fcntl.h \
		    stdlib.h \
		    string.h \
		    unistd.h \
		    elf.h \
		    CUnit/CUnit.h \
		    libxml/xmlwriter.h\
                    udis86.h])

CFLAGS="$CFLAGS_BK"
CPPFLAGS="$CPPFLAGS_BK"

if test "x$HAVE_TESTS" = "xyes"; then
   if test "x$ac_cv_header_CUnit_CUnit_h" = "xno"; then
      if test "$with_cunit_dir" != ""; then
      	 AC_MSG_ERROR(["CUnit headers not found at $with_cunit_dir/include/CUnit/CUnit.h"])
      fi
      AC_MSG_ERROR([CUnit headers not found...
     if installed, please use --with-cunit-prefix=/dir
     To install the CUnit on debian based distros use:
         sudo apt-get install libcunit1-dev

     If you doesn't want run tests, remove the --enable-tests...])
   fi
fi

if test "x$ac_cv_header_libxml_xmlwriter_h" = "xno"; then
   AC_MSG_ERROR([libxml2 headers not found at $with_libxml2_includes/libxml/xmlwriter.h
    To install the libxml2 on debian based distros use:
        sudo apt-get install libxml2-dev
    If the library is already installed, use --with-libxml2-prefix=/dir])
fi

if test "x$ac_cv_header_udis86_h" = "xno"; then
   AC_MSG_ERROR([libudis86 headers not found at $with_libudis_includes/udis86.h
    Download udis86 from http://udis86.sourceforge.net/
    If the library is already installed, use --with-libudis-prefix=/dir])
fi

INCLUDE_TESTS=
AC_SUBST(HAVE_TESTS)

if test "x$HAVE_TESTS" = "xyes"; then
   INCLUDE_TESTS=test
fi

AC_SUBST([INCLUDE_TESTS])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_MMAP
AC_CHECK_FUNCS([bzero getaddrinfo inet_ntoa memset socket munmap])

# architecture choice
TARGET_ARCH=
ARCH=
ELF_FORMAT=

if test "x$target_cpu" = "x";
then
	TARGET_ARCH="$host_cpu"
else
	TARGET_ARCH="$target_cpu"
fi

case $TARGET_ARCH in
     x86_64|amd64|*64) ARCH=64;;
     i386|i486|i586|i686|i*86) ARCH=32;;
esac

if test "x$ARCH" = "x";
then
	AC_MSG_ERROR([Invalid target architecure ($TARGET_ARCH).
	Valid architecure are:
	      - i386
	      - i486
	      - i586
	      - i686
	      - x86_64
	      - amd64
])
fi

if test "x$ARCH" = "x32";
then
	ELF_FORMAT="elf32"
elif test "x$ARCH" = "x64";
then
	ELF_FORMAT="elf64";
else
	AC_MSG_ERROR([Invalid architecture ($ARCH)])
fi

AC_SUBST([ARCH])
AC_SUBST([ELF_FORMAT])
AC_SUBST([TARGET_ARCH])

AC_CONFIG_FILES([     Makefile \
                      src/Makefile \
                      test/Makefile \
                      test/hosts/Makefile \
                      test/malwares/Makefile \
		      examples/Makefile])


AC_OUTPUT

AC_MSG_RESULT([

























01101101011000010110110001100101011011000110011001101001011000110111010101110011
00100000011010010110111001100110011001010110001101110100001000000010110101101001
00100000001011110110001001101111011011110111010000101111011101100110110101101100
01101001011011100111010101111010001000000010110101101111001000000010111101100010
01101111011011110111010000101111011101100110110101101100011010010110111001110101
01111010001011010110100101101110011001100110010101100011011101000110010101100100
00100000001011010110110100100000001100000010000000101101011100000010000001110000
01100001011100100110000101110011011010010111010001100101001011100110111100001101
00001010011010000110000101110000011100000111100100100000011010000110000101100011
01101011011010010110111001100111001000000010000100100001001000010000110100001010
00001101000010100100001001110101011001110101001101100101011000110010000001010100
01100101011000010110110100001101000010100000110100001010011010010011010001101011
00101100001000000110001100110000001100000110110000110011011100100010110000100000
01101101001100000110111001100001011001000010110000100000011100110110100101100111
01110011011001010110011101110110001011000010000001110011011011000111100101100110
01110101011011100110101101111001001011000010000001100010001011010110110101100001
01101110000011010000101000001101000010100000110100001010000011010000101000001101
0001          MalELFicus - Malware Development and Analysis Tool            0010
0011                                                                        0100
0101 Configuration:                                                         0110])

if test "x$HAVE_TESTS" = "xyes"; then
   AC_MSG_RESULT([0111    Unit tests: enabled                                                 1000])
else
   AC_MSG_RESULT([0111    Unit tests: disabled (use ./configure --enable-tests to enable      1000])
fi

if test "x$HAVE_NASM" = "xtrue"; then
   AC_MSG_RESULT([1001    NASM: installed                                                     1010])
else
   AC_MSG_RESULT([1001    NASM: not installed... required to run tests                        1010])
fi
   AC_MSG_RESULT([10111100110111101111000000010010001100100010101100111100010011010101111001101111])
   AC_MSG_RESULT([        Build configuration])
   AC_MSG_RESULT([            TARGET_CPU: $target_cpu])
   AC_MSG_RESULT([            HOST_CPU: $host_cpu])
   AC_MSG_RESULT([            ELF_FORMAT: $ELF_FORMAT])
