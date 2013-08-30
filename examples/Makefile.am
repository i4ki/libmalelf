###########################################################################
# Some rules for building asm files:

SUFFIXES = .asm

.asm.o:
	nasm -f bin $< -o $@
###########################################################################

bin_PROGRAMS = 	writing_binaries \
		creating_elf \
		get_section_names \
		show_ehdr_members \
		disas_binary \
		text_section \
		infect

# hack to force automake to don't link the assembled binary
text_section_LINK = 	@cp text_section.o text_section.bin; \
			echo "link a flat binary? hacking autohell ..."

disas_binary_SOURCES = disas_binary.c
writing_binaries_SOURCES = writing_binaries.c
creating_elf_SOURCES = creating_elf.c
get_section_names_SOURCES = get_section_names.c
show_ehdr_members_SOURCES = show_ehdr_members.c
text_section_SOURCES = text_section.asm
infect_SOURCES = infect.c

AM_CFLAGS = -ggdb -Wall -Wextra -Werror -I../src/include
LDADD = -L../src/.libs -lmalelf
