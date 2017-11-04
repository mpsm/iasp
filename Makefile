CFLAGS+= -Wall -Werror
LDFLAGS+= -L libiasp -static-libgcc
CC?= gcc

# set DEBUG options
ifndef IASP_DEBUG
IASP_DEBUG=0
endif

ifeq ($(IASP_DEBUG), 1)
CFLAGS+= -O0 -g -DIASP_DEBUG=1
else
CFLAGS+= -Os
endif

# set openssl include path
ifdef OPENSSL_PATH
CFLAGS+=-I $(OPENSSL_PATH)/include
LDFLAGS+= -L $(OPENSSL_PATH)
endif

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
