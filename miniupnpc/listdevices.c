/* $Id$ */
/* Project : miniupnp
 * Author : Thomas Bernard
 * Copyright (c) 2013 Thomas Bernard
 * This software is subject to the conditions detailed in the
 * LICENCE file provided in this distribution. */

#include <stdio.h>
#include <string.h>
#include "miniupnpc.h"

int main(int argc, char * * argv)
{
	const char * multicastif = 0;
	const char * minissdpdpath = 0;
	int ipv6 = 0;
	int error = 0;
	struct UPNPDev * devlist = 0;
	struct UPNPDev * dev;
	int i;

	for(i = 1; i < argc; i++) {
		if(strcmp(argv[i], "-6") == 0)
			ipv6 = 1;
		else {
			printf("usage : %s [options]\n", argv[0]);
			printf("   -6 : use IPv6\n");
			return 1;
		}
	}

	devlist = upnpDiscoverAll(2000, multicastif, minissdpdpath,
	                             0/*sameport*/, ipv6, &error);
	if(devlist) {
		for(dev = devlist; dev != NULL; dev = dev->pNext) {
			printf("%s\t%s\n", dev->st, dev->descURL);
		}
		freeUPNPDevlist(devlist);
	} else {
		printf("no device found.\n");
	}

	return 0;
}

