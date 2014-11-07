# $Id: Makefile,v 1.9 2014/11/04 22:25:00 nanard Exp $
# MiniUPnP Project
# http://miniupnp.free.fr/
# (c) 2005-2014 Thomas Bernard
# to install use :
# $ PREFIX=/tmp/dummylocation make install
# or
# $ INSTALLPREFIX=/usr/local make install
# or 
# make install (will go to /usr/bin, /usr/lib, etc...)
CC = gcc
#AR = gar
CFLAGS = -O0 -g -DDEBUG
#CFLAGS = -O
CFLAGS += -fPIC
CFLAGS += -ansi
CFLAGS += -Wall -W
CFLAGS += -D_BSD_SOURCE
CFLAGS += -DUPNPC_USE_SELECT
INSTALL = install
#following libs are needed on Solaris
#LDLIBS=-lsocket -lnsl -lresolv

# APIVERSION is used to build SONAME
APIVERSION = 0

SRCS = miniupnpc-async.c parsessdpreply.c \
       upnputils.c igd_desc_parse.c minixml.c \
       upnpreplyparse.c \
       testasync.c

LIBOBJS = miniupnpc-async.o parsessdpreply.o \
          upnputils.o igd_desc_parse.o minixml.o \
          upnpreplyparse.o

OBJS = $(patsubst %.c,%.o,$(SRCS))

# HEADERS to install
HEADERS = miniupnpc-async.h
LIBRARY = libminiupnpc-async.a
SHAREDLIBRARY = libminiupnpc-async.so
SONAME = $(SHAREDLIBRARY).$(APIVERSION)
EXECUTABLES = testasync

INSTALLPREFIX ?= $(PREFIX)/usr
INSTALLDIRINC = $(INSTALLPREFIX)/include/miniupnpc
INSTALLDIRLIB = $(INSTALLPREFIX)/lib
INSTALLDIRBIN = $(INSTALLPREFIX)/bin

.PHONY:	install clean depend all installpythonmodule

all:	$(LIBRARY) $(EXECUTABLES)

pythonmodule:	$(LIBRARY) miniupnpcmodule.c setup.py
	python setup.py build
	touch $@

installpythonmodule:	pythonmodule
	python setup.py install

clean:
		$(RM) $(LIBRARY) $(SHAREDLIBRARY) $(EXECUTABLES) $(OBJS)
		# clean python stuff
		$(RM) pythonmodule
		$(RM) -r build/ dist/
		#python setup.py clean

install:	$(LIBRARY) $(SHAREDLIBRARY)
	$(INSTALL) -d $(INSTALLDIRINC)
	$(INSTALL) -m 644 $(HEADERS) $(INSTALLDIRINC)
	$(INSTALL) -d $(INSTALLDIRLIB)
	$(INSTALL) -m 644 $(LIBRARY) $(INSTALLDIRLIB)
	$(INSTALL) -m 644 $(SHAREDLIBRARY) $(INSTALLDIRLIB)/$(SONAME)
	$(INSTALL) -m 755 upnpc-shared $(INSTALLDIRBIN)/upnpc
	ln -fs $(SONAME) $(INSTALLDIRLIB)/$(SHAREDLIBRARY)

cleaninstall:
	$(RM) -r $(INSTALLDIRINC)
	$(RM) $(INSTALLDIRLIB)/$(LIBRARY)
	$(RM) $(INSTALLDIRLIB)/$(SHAREDLIBRARY)

depend:
	makedepend -Y -- $(CFLAGS) -- $(SRCS) 2>/dev/null

$(LIBRARY):	$(LIBOBJS)
	$(AR) crs $@ $?

$(SHAREDLIBRARY):	$(LIBOBJS)
	$(CC) -shared -Wl,-soname,$(SONAME) -o $@ $^

upnpc-static:	upnpc.o $(LIBRARY)
	$(CC) -o $@ $^

upnpc-shared:	upnpc.o $(SHAREDLIBRARY)
	$(CC) -o $@ $^

#testasync:	testasync.o libminiupnpc-async.a
testasync:	testasync.o -lminiupnpc-async

# DO NOT DELETE THIS LINE -- make depend depends on it.

miniupnpc-async.o: miniupnpc-async.h declspec.h parsessdpreply.h upnputils.h
parsessdpreply.o: parsessdpreply.h
testasync.o: miniupnpc-async.h declspec.h
