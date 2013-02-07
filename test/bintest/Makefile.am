bin_PROGRAMS = uninfected uninfected_asm

uninfected_SOURCES = uninfected.c
uninfected_asm_SOURCES = uninfected_asm.s

CCAS = nasm
AM_CCASFLAGS = -f elf
AM_CFLAGS = -Wall -Wextra -Werror

uninfected_asm_CCASFLAGS = -f elf

%.o: %.s
	$(CCAS) $(CCASFLAGS) -o $@ $<