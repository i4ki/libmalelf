###########################################################################
# Some rules for building asm files:

SUFFIXES = .asm

.asm.o:
	nasm -f $(ELF_FORMAT) $< -o $@
###########################################################################

bin_PROGRAMS = uninfected uninfected_asm

uninfected_SOURCES = uninfected.c
uninfected_asm_SOURCES = uninfected_asm.asm

AM_CFLAGS = -Wall -Wextra -Werror
uninfected_asm_LINK = ld -o uninfected_asm

