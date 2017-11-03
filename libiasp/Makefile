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
	tp.c

INCS= iasp_field.h
OBJS= $(patsubst %.c,%.o,$(SRCS))

AR?= ar
CC?= gcc
CFLAGS+= -O0 -g -Wall -Werror

LIBNAME= libiasp

all: $(LIBNAME).a

$(LIBNAME).a: $(OBJS)
	$(AR) rcvs $@ $^

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	rm -f $(OBJS) $(LIBNAME).a
	
.PHONY: clean all
