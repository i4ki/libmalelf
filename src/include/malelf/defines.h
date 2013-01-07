#ifndef MALELF_DEFINES_H
#define MALELF_DEFINES_H

#ifdef __cplusplus
# define MALELF_BEGIN_DECLS extern "C" {
# define MALELF_END_DECLS }
#else
# define MALELF_BEGIN_DECLS /* empty */
# define MALELF_END_DECLS /* empty */
#endif

/* Unused variables */
#define UNUSED(x) (void) x

/* ELF Architecture Type */
#define MALELF_ELF32 ELFCLASS32
#define MALELF_ELF64 ELFCLASS64
#define MALELF_ELFNONE ELFCLASSNONE

/* System-function used to allocate buffer */
#define MALELF_ALLOC_MMAP 0
#define MALELF_ALLOC_MALLOC 1

#endif /* MALELF_DEFINES_H */
