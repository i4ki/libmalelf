# malelf/defines.h

# Binary format type
FMT_ELF = 0
FMT_FLAT = 1

# Binary ELF class
ELF = 0
ELFNONE = 0
ELF32 = 1
ELF64 = 2

# Flat binary classes
FLAT = (1 + ELF64)
FLATUNKNOWN = FLAT
FLAT32 = (1 + FLAT)
FLAT64 = (1 + FLAT32)

# alloc type for binary open methods
ALLOC_NONE = 0
ALLOC_MMAP = 1
ALLOC_MALLOC = 2

ORIGIN = (0x08048000)

MAGIC_BYTES = (0x37333331)
PAGE_SIZE = (4096)
