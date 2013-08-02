from malelf.binary import MalelfBinary

binary = MalelfBinary()
print binary.open("/bin/ls")
binary.close()
