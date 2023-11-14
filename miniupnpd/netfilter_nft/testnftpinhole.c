/* $Id: testnftpinhole.c,v 1.2 2019/06/30 19:49:18 nanard Exp $ */
/* MiniUPnP project
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * (c) 2012-2023 Thomas Bernard
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <syslog.h>

#include "config.h"
#include "../miniupnpdtypes.h"
#include "nftpinhole.h"
#include "../commonrdr.h"
#include "../upnputils.h"

struct lan_addr_list lan_addrs;
time_t startup_time = 0;

int main(int argc, char * * argv)
{
	int uid;
	const char * ifname = "eth0";
	const char * rem_host = "2a00::dead:beaf";
	unsigned short rem_port = 1911;
	const char * int_client = "fe80::1023:4095";
	unsigned short int_port = 34952;
	char desc[1024] = { 0 };
	unsigned int timestamp = 0;

	openlog("testnftpinhole", LOG_PERROR|LOG_CONS, LOG_LOCAL0);

	uid = add_pinhole(ifname, rem_host, rem_port, int_client, int_port, IPPROTO_TCP,
	                  "dummy description", upnp_time() + 60 /* timestamp */);
	syslog(LOG_INFO, "add_pinhole(): uid=%d", uid);

	uid = find_pinhole(ifname, rem_host, rem_port, int_client, int_port, IPPROTO_TCP,
	                   desc, sizeof(desc), &timestamp);
	syslog(LOG_INFO, "find_pinhole(): uid=%d desc=\"%s\" timestamp=%u", uid, desc, timestamp);
	return 0;
}

