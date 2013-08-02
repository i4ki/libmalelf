CFLAGS="-I../src/include"
LDFLAGS="-L../src/.libs -lmalelf"
MALELF="malelf/"

all:
	 python setup.py build_ext -i

clean:
	rm -rf build/* malelf/*.c malelf/*.so malelf/*.pyc
