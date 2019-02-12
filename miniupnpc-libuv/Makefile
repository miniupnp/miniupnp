# tested with GNU Make
PKG_CONFIG ?= pkg-config

CFLAGS += -g
CFLAGS += -Wall -Wextra
CFLAGS += $(shell $(PKG_CONFIG) libuv --cflags)
LDFLAGS += $(shell $(PKG_CONFIG) libuv --libs-only-L)
LDLIBS += $(shell $(PKG_CONFIG) libuv --libs-only-l)

OBJS = minissdpc-libuv.o example.o
BIN = example

.PHONY:	all clean

all:	$(BIN)

clean:
	$(RM) $(BIN) $(OBJS)

$(BIN):	$(OBJS)
