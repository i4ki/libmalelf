from binary import MalelfBinary

bin = MalelfBinary()
print bin.open("/bin/ls")
bin.close()
