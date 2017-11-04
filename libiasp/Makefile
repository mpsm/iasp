IASP_CRYPTO?= openssl
IASP_NETWORK?= posix

SRCS= \
	streambuf.c \
	encode.c \
	binbuf.c \
	crypto-$(IASP_CRYPTO).c \
	network-$(IASP_NETWORK).c \
	proto.c \
	session.c \
	iasp.c \
	decode.c \
	tp.c \
	debug.c

INCS= iasp_field.h
OBJS= $(patsubst %.c,%.o,$(SRCS))

AR?= ar
CC?= gcc
CFLAGS+= -Wall -Werror

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
endif

LIBNAME= libiasp

all: $(LIBNAME).a

$(LIBNAME).a: $(OBJS)
	$(AR) rcvs $@ $^

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	rm -f $(OBJS) $(LIBNAME).a
	
.PHONY: clean all
