/* $Id: testpfpinhole.c,v 1.3 2012/04/19 22:02:12 nanard Exp $ */
/* MiniUPnP project
 * http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * (c) 2006-2012 Thomas Bernard
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <syslog.h>

#include "obsdrdr.h"
#include "pfpinhole.h"

int runtime_flags = 0;
const char * tag = NULL;

const char * anchor_name = "miniupnpd";
const char * queue = NULL;

int main(int argc, char * *argv)
{
	int uid;
	int ret;

	openlog("testpfpinhole", LOG_PERROR, LOG_USER);
	if(init_redirect() < 0) {
		fprintf(stderr, "init_redirect() failed\n");
		return 1;
	}

	uid = add_pinhole("ep0", "2001::1:2:3", 12345, "123::ff", 54321, IPPROTO_UDP);
	if(uid < 0) {
		fprintf(stderr, "add_pinhole() failed\n");
	}
	printf("add_pinhole() returned %d\n", uid);
	uid = add_pinhole("ep0", NULL, 0, "dead:beef::42:42", 8080, IPPROTO_UDP);
	if(uid < 0) {
		fprintf(stderr, "add_pinhole() failed\n");
	}
	printf("add_pinhole() returned %d\n", uid);

	ret = delete_pinhole(1);
	printf("delete_pinhole() returned %d\n", ret);
	ret = delete_pinhole(2);
	printf("delete_pinhole() returned %d\n", ret);
	return 0;
}

