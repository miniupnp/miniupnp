# $Id: Makefile,v 1.2 2014/11/08 17:12:15 nanard Exp $

CFLAGS = -O0 -g -DDEBUG
# libevent debug
CFLAGS += -DUSE_DEBUG

CFLAGS += -fPIC
CFLAGS += -ansi
CFLAGS += -Wall -W
CFLAGS += -D_BSD_SOURCE
CFLAGS += -D_POSIX_C_SOURCE=1

LDFLAGS = -levent

LIB = libminiupnpc-ev.a

LIB_SRCS = miniupnpc-libevent.c minixml.c igd_desc_parse.c upnpreplyparse.c

SRCS = $(LIB_SRCS) upnpc-libevent.c

LIB_OBJS = $(patsubst %.c,%.o,$(LIB_SRCS))

OBJS = $(patsubst %.c,%.o,$(SRCS))

EXECUTABLE = upnpc-libevent

.PHONY:	all clean depend

all:	$(EXECUTABLE)

clean:
	$(RM) $(OBJS)
	$(RM) $(EXECUTABLE)

upnpc-libevent:	upnpc-libevent.o $(LIB)

$(LIB):	$(LIB_OBJS)
	$(AR) crs $@ $?

depend:
	makedepend -Y -- $(CFLAGS) -- $(SRCS) 2>/dev/null

# DO NOT DELETE THIS LINE -- make depend depends on it.

miniupnpc-libevent.o: miniupnpc-libevent.h declspec.h upnpreplyparse.h
miniupnpc-libevent.o: minixml.h igd_desc_parse.h
minixml.o: minixml.h
igd_desc_parse.o: igd_desc_parse.h
upnpreplyparse.o: upnpreplyparse.h minixml.h
upnpc-libevent.o: miniupnpc-libevent.h declspec.h upnpreplyparse.h
