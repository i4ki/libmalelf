cimport cehdr

cdef class MalelfEhdr:
    cdef cehdr.MalelfEhdr _c_ehdr
    cdef cehdr.MalelfEhdrTable _c_ehdr_t

    def type(self):
        #cehdr.malelf_ehdr_get_type(&self._c_ehdr, &self._c_ehdr_t)
        #return selfehdt.name, ad
        return 1

    def machine(self):
        return 1

    def version(self):
        return 1

    def shoff(self):
        return 1

    def phoff(self):
        return 1

    def entry(self):
        return 1

    def size(self):
        return 1

    def phentsize(self):
        return 1

    def shentsize(self):
        return 1

    def phnum(self):
        return 1

    def shnum(self):
        return 1

    def shstrndx(self):
        return 1

    def flags(self):
        return 1

    def set_entry_point(self, int entry_point):
        return 1

