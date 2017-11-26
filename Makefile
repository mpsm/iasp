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

SRCS:= $(wildcard *.c)
OBJS:= $(SRCS:.c=.o)

TARGET:= iaspdemo

all: $(TARGET)

$(TARGET): libiasp/libiasp.a

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) $^ -liasp -lcrypto -lconfig -ldl -o $@ 

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

libiasp/libiasp.a libiasp/libiasp.so: force
	(cd libiasp && make $(notdir $@))

force:
	@true

clean:
	(cd libiasp && make clean)
	rm -f $(OBJS)

distclean: clean
	rm -f $(OBJS)

.PHONY: clean all true
