IASP_CRYPTO?= openssl

SRCS= field.c \
	streambuf.c \
	binbuf.c \
	crypto-$(IASP_CRYPTO).c

INCS= iasp_field.h
OBJS= $(patsubst %.c,%.o,$(SRCS))

AR?= ar
CC?= gcc
CFLAGS+= -O0 -g -Wall -Werror -fpic

LIBNAME= libiasp

all: $(LIBNAME).a $(LIBNAME).so

$(LIBNAME).so: $(OBJS)
	$(CC) -shared -o $@ $^

$(LIBNAME).a: $(OBJS)
	$(AR) rcvs $@ $^

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	rm -f $(OBJS) $(LIBNAME).a $(LIBNAME).so
	
.PHONY: clean all