# $Id: Makefile,v 1.19 2014/06/10 10:00:18 nanard Exp $
# MiniUPnP project
# author: Thomas Bernard
# website: http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
# for use with GNU Make (gmake)
# install with :
# $ PREFIX=/tmp/dummylocation make install
# or
# $ INSTALLPREFIX=/usr/local make install
# or
# make install (miniupnpd will be put in /usr/sbin)
#
# install target is made for linux... sorry BSD users...
#CFLAGS = -g
CFLAGS ?= -Os
CFLAGS += -Wall
CFLAGS += -W -Wstrict-prototypes
CFLAGS += -fno-strict-aliasing -fno-common
CFLAGS += -D_GNU_SOURCE
CFLAGS += -ansi
CC = gcc
RM = rm -f
INSTALL = install
OS = $(shell uname -s)

#EXECUTABLES = minissdpd testminissdpd listifaces
EXECUTABLES = minissdpd testminissdpd testcodelength
MINISSDPDOBJS = minissdpd.o openssdpsocket.o daemonize.o upnputils.o ifacewatch.o
TESTMINISSDPDOBJS = testminissdpd.o

ALLOBJS = $(MINISSDPDOBJS) $(TESTMINISSDPDOBJS) testcodelength.o

INSTALLPREFIX ?= $(PREFIX)/usr
SBININSTALLDIR = $(INSTALLPREFIX)/sbin
MANINSTALLDIR = $(INSTALLPREFIX)/share/man


.PHONY:	all clean install depend

all:	$(EXECUTABLES)

clean:
	$(RM) $(ALLOBJS) $(EXECUTABLES)

install:	minissdpd
	$(INSTALL) -d $(SBININSTALLDIR)
	$(INSTALL) minissdpd $(SBININSTALLDIR)
	$(INSTALL) -d $(MANINSTALLDIR)/man1
	$(INSTALL) minissdpd.1 $(MANINSTALLDIR)/man1/minissdpd.1
ifneq ($(OS), Darwin)
	$(INSTALL) -d $(PREFIX)/etc/init.d
	$(INSTALL) minissdpd.init.d.script $(PREFIX)/etc/init.d/minissdpd
endif

minissdpd: $(MINISSDPDOBJS)
	if [ "$(DEB_BUILD_ARCH_OS)" = "kfreebsd" ] ; then \
		$(CC) $(CFLAGS) $(LDFLAGS) -lfreebsd-glue -o $@ $(MINISSDPDOBJS) ; \
	else \
		$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(MINISSDPDOBJS) ; \
	fi

testminissdpd:	$(TESTMINISSDPDOBJS)

testcodelength:	testcodelength.o

listifaces:	listifaces.o upnputils.o

depend:
	makedepend -f$(MAKEFILE_LIST) -Y \
	$(ALLOBJS:.o=.c) 2>/dev/null

# DO NOT DELETE

minissdpd.o: config.h upnputils.h openssdpsocket.h daemonize.h codelength.h
minissdpd.o: ifacewatch.h
openssdpsocket.o: config.h openssdpsocket.h
daemonize.o: daemonize.h config.h
upnputils.o: config.h upnputils.h
ifacewatch.o: config.h openssdpsocket.h
testcodelength.o: codelength.h
