all: unittest libiasp/libiasp.so

test: clean unittest
	./unittest

unittest: libiasp/libiasp.a test.c
	gcc -g -O0 -static -Wall -Werror -L libiasp test.c -liasp -lcmocka -lgcov -o $@


libiasp/libiasp.a libiasp/libiasp.so: force
	(cd libiasp && make $(notdir $@))

force:
	true

clean:
	(cd libiasp && make clean)
	rm -f unittest

.PHONY: clean all test true
