from malelf.binary import MalelfBinary
from malelf.ehdr import MalelfEhdr

binary = MalelfBinary()
print binary.open("/bin/ls")
ehdr = MalelfEhdr()
print ehdr.get_type()
binary.close()
