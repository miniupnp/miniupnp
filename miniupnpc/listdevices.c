/* $Id: listdevices.c,v 1.3 2015/05/22 10:14:04 nanard Exp $ */
/* Project : miniupnp
 * Author : Thomas Bernard
 * Copyright (c) 2013-2014 Thomas Bernard
 * This software is subject to the conditions detailed in the
 * LICENCE file provided in this distribution. */

#include <stdio.h>
#include <string.h>
#include "miniupnpc.h"

int main(int argc, char * * argv)
{
	const char * searched_device = NULL;
	const char * * searched_devices = NULL;
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
		else if(strcmp(argv[i], "-d") == 0) {
			if(++i >= argc) {
				fprintf(stderr, "-d option needs one argument\n");
				return 1;
			}
			searched_device = argv[i];
		} else if(strcmp(argv[i], "-l") == 0) {
			if(++i >= argc) {
				fprintf(stderr, "-l option needs at least one argument\n");
				return 1;
			}
			searched_devices = (const char * *)(argv + i);
			break;
		} else if(strcmp(argv[i], "-m") == 0) {
			if(++i >= argc) {
				fprintf(stderr, "-m option needs one argument\n");
				return 1;
			}
			multicastif = argv[i];
		} else {
			printf("usage : %s [options] [-l <device1> <device2> ...]\n", argv[0]);
			printf("options :\n");
			printf("   -6 : use IPv6\n");
			printf("   -m address/ifname : network interface to use for multicast\n");
			printf("   -d <device string> : search only for this type of device\n");
			printf("   -l <device1> <device2> ... : search only for theses types of device\n");
			printf("   -h : this help\n");
			return 1;
		}
	}

	if(searched_device) {
		printf("searching UPnP device type %s\n", searched_device);
		devlist = upnpDiscoverDevice(searched_device,
		                             2000, multicastif, minissdpdpath,
		                             0/*sameport*/, ipv6, &error);
	} else if(searched_devices) {
		printf("searching UPnP device types :\n");
		for(i = 0; searched_devices[i]; i++)
			printf("\t%s\n", searched_devices[i]);
		devlist = upnpDiscoverDevices(searched_devices,
		                              2000, multicastif, minissdpdpath,
		                              0/*sameport*/, ipv6, &error, 1);
	} else {
		printf("searching all UPnP devices\n");
		devlist = upnpDiscoverAll(2000, multicastif, minissdpdpath,
		                             0/*sameport*/, ipv6, &error);
	}
	if(devlist) {
		for(dev = devlist; dev != NULL; dev = dev->pNext) {
			printf("%-48s\t%s\n", dev->st, dev->descURL);
		}
		freeUPNPDevlist(devlist);
	} else {
		printf("no device found.\n");
	}

	return 0;
}

