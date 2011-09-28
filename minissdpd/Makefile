# $Id: Makefile,v 1.13 2011/07/29 15:21:12 nanard Exp $
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
#CFLAGS = -Wall -g -D_GNU_SOURCE -Wstrict-prototypes 
CFLAGS = -Wall -Os -D_GNU_SOURCE -fno-strict-aliasing -Wstrict-prototypes
CC = gcc
RM = rm -f
INSTALL = install

#EXECUTABLES = minissdpd testminissdpd listifaces
EXECUTABLES = minissdpd testminissdpd testcodelength
MINISSDPDOBJS = minissdpd.o openssdpsocket.o daemonize.o upnputils.o ifacewatch.o
TESTMINISSDPDOBJS = testminissdpd.o

ALLOBJS = $(MINISSDPDOBJS) $(TESTMINISSDPDOBJS) testcodelength.o

INSTALLPREFIX ?= $(PREFIX)/usr
SBININSTALLDIR = $(INSTALLPREFIX)/sbin

.PHONY:	all clean install depend

all:	$(EXECUTABLES)

clean:
	$(RM) $(ALLOBJS) $(EXECUTABLES)

install:	minissdpd
	$(INSTALL) -d $(SBININSTALLDIR)
	$(INSTALL) minissdpd $(SBININSTALLDIR)
	$(INSTALL) -d $(PREFIX)/etc/init.d
	$(INSTALL) minissdpd.init.d.script $(PREFIX)/etc/init.d/minissdpd

minissdpd: $(MINISSDPDOBJS)
	$(CC) $(CFLAGS) -o $@ $(MINISSDPDOBJS)

testminissdpd:	$(TESTMINISSDPDOBJS)

testcodelength:	testcodelength.o

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
