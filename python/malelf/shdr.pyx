cimport cshdr

cdef class MalelfShdr:
    cdef cshdr.MalelfShdr _c_shdr
    cdef cshdr.MalelfShdrType _c_shdr_t

