# $Id: Makefile,v 1.2 2009/08/20 09:31:10 nanard Exp $
CC=gcc
CFLAGS=-Wall -g -I.
RM=rm -f

all:	testipfwrdr 

clean:
	$(RM) *.o testipfwrdr

testipfwrdr:	testipfwrdr.o ipfwrdr.o
	$(CC) -o $@ $^

ipfwrdr.o:	ipfwrdr.c ix2015-func.c ipfwaux.h ipfwrdr.h

testipfwrdr.o:	testipfwrdr.c


