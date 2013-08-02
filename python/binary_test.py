from malelf.binary import MalelfBinary
from malelf.defines import AllocType
#from malelf.ehdr import MalelfEhdr

binary = MalelfBinary()
binary.set_alloc_type(AllocType.MMAP)
print binary.open("/bin/ls")

#ehdr = MalelfEhdr()
#ehdr.set_binary(binary)

#ehdr = binary.get_ehdr()

#name, value, meaning = ehdr.get_type()

#print name

binary.close()
