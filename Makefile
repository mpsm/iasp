all: test libiasp/libiasp.so

test: unittest
	./unittest

unittest: libiasp/libiasp.a test.c
	gcc -g -O0 -static -Wall -Werror -L libiasp test.c -liasp -lcmocka -o $@


libiasp/libiasp.a libiasp/libiasp.so:
	(cd libiasp && make $(notdir $@))


clean:
	(cd libiasp && make clean)
	rm -f test

.PHONY: clean all test
