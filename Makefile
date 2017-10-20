all: test libiasp/libiasp.so


test: libiasp/libiasp.a
	gcc -Wall -Werror -L libiasp test.c -liasp -o $@


libiasp/libiasp.a libiasp/libiasp.so:
	(cd libiasp && make $(notdir $@))


clean:
	(cd libiasp && make clean)
	rm -f test
