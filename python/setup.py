# build script for 'dvedit' - Python libdv wrapper

# change this as needed
libmalelf_Includedir = "../src/include"

import sys
import os
from distutils.core import setup
from distutils.extension import Extension

# we'd better have Cython installed, or it's a no-go
try:
    from Cython.Distutils import build_ext
except:
    print "You don't seem to have Cython installed. Please get a"
    print "copy from www.cython.org and install it"
    sys.exit(1)


# scan the 'malelf' directory for extension files, converting
# them to extension names in dotted notation
def scandir(_dir, files=[]):
    for filename in os.listdir(_dir):
        path = os.path.join(_dir, filename)
        if os.path.isfile(path) and path.endswith(".pyx"):
            files.append(path.replace(os.path.sep, ".")[:-4])
        elif os.path.isdir(path):
            scandir(path, files)
    return files


# generate an Extension object from its dotted name
def makeExtension(extName):
    extPath = extName.replace(".", os.path.sep)+".pyx"
    return Extension(
        extName,
        [extPath],
        include_dirs=[libmalelf_Includedir, "."],
        extra_compile_args=["-O3", "-Wall"],
        extra_link_args=['-L../src/.libs'],
        libraries=["malelf"],
    )

# get the list of extensions
extNames = scandir("malelf")

# and build up the set of Extension objects
extensions = [makeExtension(name) for name in extNames]

# finally, we can pass all this to distutils
setup(
    name="malelf",
    packages=["malelf"],
    ext_modules=extensions,
    cmdclass={'build_ext': build_ext},
)

#from distutils.core import setup
#from distutils.extension import Extension
#from Cython.Distutils import build_ext

#setup(
#    cmdclass = {'build_ext': build_ext},
#    ext_modules = [Extension("malelf", ["malelf/binary.pyx"])]
#)
