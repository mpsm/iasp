TOP := $(dir $(lastword $(MAKEFILE_LIST)))

# library sources and objects
LIBSRCS= $(addprefix libiasp/,\
	streambuf.c \
	encode.c \
	binbuf.c \
	proto.c \
	iasp.c \
	decode.c \
	tp.c \
	debug.c \
	security.c \
	spn.c \
	peer.c \
	crypto-openssl.c \
	network-posix.c)
LIBINCS= iasp_field.h
LIBOBJS= $(patsubst %.c,%.o,$(LIBSRCS))
LIBLOBJS= $(patsubst %.c,%.lo,$(LIBSRCS))
LIBNAME= libiasp

# app sources and objects
APPSRCS= $(addprefix apps/,\
	 pki.c \
	 iaspdemo.c)
APPOBJS= $(patsubst %.c,%.o,$(APPSRCS))
APPNAME= iaspdemo

# determine install location
PREFIX?= /usr
LIBDIR= $(PREFIX)/lib
INCDIR= $(PREFIX)/include

# setup toolchain
AR?= ar
CC?= gcc
CFLAGS+= -Wall -Werror
LDFLAGS+= -liasp -lconfig -lcrypto -ldl -lrt

# set DEBUG options
ifndef IASP_DEBUG
IASP_DEBUG=0
endif
ifeq ($(IASP_DEBUG), 1)
CFLAGS+= -O0 -g -DIASP_DEBUG=1
else
CFLAGS+= -Os
endif

# set custom (devel) libiasp path
ifdef LIBIASP_PATH
CFLAGS+= -I $(LIBIASP_PATH)
LDFLAGS+= -L $(LIBIASP_PATH)
RPATHS+= -Wl,-rpath,$(LIBIASP_PATH)
endif

# set openssl include and library path
ifdef OPENSSL_PATH
CFLAGS+=-I $(OPENSSL_PATH)/include
LDFLAGS+= -L $(OPENSSL_PATH)
RPATHS+= -Wl,-rpath,$(OPENSSL_PATH)
endif

all: $(APPNAME) $(APPNAME)-static $(LIBNAME).so $(LIBNAME).a

$(APPNAME): $(APPOBJS) $(LIBNAME).so
	$(CC) $(APPOBJS) $(LDFLAGS) $(RPATHS) -o $@

$(APPNAME)-static: $(APPOBJS) $(LIBNAME).a
	$(CC) -static $(APPOBJS) $(LDFLAGS) -o $@

$(LIBNAME).a: $(LIBOBJS)
	$(AR) rcvs $@ $^

$(LIBNAME).so: $(LIBLOBJS)
	$(CC) -shared -o $@ $^

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

%.lo: %.c
	$(CC) -c -fPIC $(CFLAGS) $< -o $@

install-lib: $(LIBNAME).so
	install -m 755 --strip $< $(LIBDIR)/$<

install-dev: $(LIBNAME).a iasp.h
	install -m 644 $(LIBNAME).a $(LIBDIR)
	install -m 755 -d $(INCDIR)/iasp
	install -m 644 iasp.h $(INCDIR)/iasp/iasp.h

clean:
	rm -f $(LIBOBJS) $(LIBLOBJS) $(LIBNAME).a $(LIBNAME).so
	rm -f $(APPNAME) $(APPNAME)-static $(APPOBJS)
	
.PHONY: clean all
