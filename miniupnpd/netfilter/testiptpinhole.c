/* $Id: testiptpinhole.c,v 1.1 2012/04/26 13:50:48 nanard Exp $ */
/* MiniUPnP project
 * http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * (c) 2012 Thomas Bernard
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <syslog.h>

#include "../config.h"
#include "../macros.h"
#include "iptpinhole.h"
#include "../commonrdr.h"


int main(int argc, char * * argv)
{
	int r;
	UNUSED(argc); UNUSED(argv);

	openlog("testiptpinhole", LOG_PERROR|LOG_CONS, LOG_LOCAL0);

	r = add_map6_rule("eth0", NULL, 0, "ff::123", 54321, IPPROTO_TCP);
	syslog(LOG_INFO, "add_map6_rule() returned %d", r);
	r = delete_map6_rule(NULL, 0, "ff::123", 54321, IPPROTO_TCP);
	syslog(LOG_INFO, "delete_map6_rule() returned %d", r);
	return 0;
}

