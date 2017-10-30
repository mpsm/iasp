CFLAGS= -g -O0 -Wall -Werror
LDFLAGS= -L libiasp -static-libgcc
CC?= gcc

all: unittest iasp

test: clean unittest
	./unittest

iasp: iasp.o libiasp/libiasp.a
	$(CC) $(LDFLAGS) $< -liasp -lcrypto -lconfig -ldl -o $@ 

unittest: test.o libiasp/libiasp.a 
	$(CC) $(LDFLAGS) $< -liasp -lcmocka -o $@

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

libiasp/libiasp.a libiasp/libiasp.so: force
	(cd libiasp && make $(notdir $@))

force:
	@true

clean:
	(cd libiasp && make clean)
	rm -f test.o iasp.o
	rm -f unittest iasp

.PHONY: clean all test true
