/* $Id: testnftpinhole.c,v 1.4 2024/03/19 23:35:54 nanard Exp $ */
/* MiniUPnP project
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * (c) 2012-2024 Thomas Bernard
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

static void print_infos(void)
{
	char rem_host[64];
	unsigned short rem_port;
	char int_client[64];
	unsigned short int_port;
	int proto, i;
	char desc[256];
	unsigned int timestamp;
	u_int64_t packets;

	for (i = 0; get_map6_rule_at(i, rem_host, sizeof(rem_host), &rem_port,
	                                int_client, sizeof(int_client), &int_port,
	                                &proto, desc, sizeof(desc)) == 0; i++) {
		packets = 0;
		get_map6_packets(rem_host, rem_port, int_client, int_port, proto, &packets);
		syslog(LOG_INFO, "pinhole %d : [%s]:%hu => [%s]:%hu %s desc \"%s\" ts=%u packets=%llu",
		       i, rem_host, rem_port, int_client, int_port,
		       proto == IPPROTO_TCP ? "tcp" : "udp", desc, timestamp,
		       (long long unsigned)packets);
	}
}

int main(int argc, char * * argv)
{
	int r;
	const char * ifname = "eth0";
	const char * rem_host = "2a00::dead:beaf";
	unsigned short rem_port = 1911;
	const char * int_client = "fe80::1023:4095";
	unsigned short int_port = 34952;

	openlog("testnftpinhole", LOG_PERROR|LOG_CONS, LOG_LOCAL0);

	r = init_redirect();
	if (r < 0) {
		syslog(LOG_ERR, "init_redirect() failed");
		return 1;
	}

	r = add_map6_rule(ifname, rem_host, rem_port, int_client, int_port, IPPROTO_TCP,
	                     "dummy description", upnp_time() + 60 /* timestamp */);
	syslog(LOG_INFO, "add_map6_rule() returned %d", r);
	print_infos();

	r = delete_map6_rule(rem_host, rem_port, int_client, int_port, IPPROTO_TCP);
	syslog(LOG_INFO, "delete_map6_rule() returned %d", r);
	print_infos();

	shutdown_redirect();

	return 0;
}
