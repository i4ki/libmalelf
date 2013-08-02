cimport cbinary

cdef class MalelfBinary:
    cdef cbinary.MalelfBinary _c_binary
    def __cinit__(self):
        cbinary.malelf_binary_init(&self._c_binary)

    def __status(self, status):
        return not status

    def open(self, char* fname):
        return self.__status(cbinary.malelf_binary_open(&self._c_binary,
                                                        fname))

    def close(self):
        cbinary.malelf_binary_close(&self._c_binary)

    def __dealloc__(self):
        cbinary.malelf_binary_close(&self._c_binary)
