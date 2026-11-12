/* $Id: testpfpinhole.c,v 1.16 2024/06/22 16:48:54 nanard Exp $ */
/* vim: tabstop=4 shiftwidth=4 noexpandtab
 * MiniUPnP project
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * (c) 2012-2024 Thomas Bernard
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <syslog.h>

#include "config.h"
#include "obsdrdr.h"
#include "pfpinhole.h"
#include "../miniupnpdtypes.h"

int runtime_flags = 0;
time_t startup_time = 0;
const char * tag = NULL;

const char * anchor_name = "miniupnpd";
const char * queue = NULL;

const char * use_ext_ip_addr = "42.42.42.42";

struct lan_addr_list lan_addrs;

#ifdef ENABLE_IPV6
static void print_pinholes(void)
{
	int i;
	char rem_host[64];
	unsigned short rem_port;
	char int_client[64];
	unsigned short int_port;
	int proto;
	unsigned int timestamp;
	u_int64_t packets;
	char desc[64];

	for(i = 0; get_pinhole_rule_at(i, rem_host, sizeof(rem_host), &rem_port,
	                               int_client, sizeof(int_client), &int_port,
	                               &proto, desc, sizeof(desc), &timestamp) == 0; i++) {
		packets = 0;
		get_pinhole_packets(rem_host, rem_port, int_client, int_port, proto, &packets);
		printf("pinhole %d : [%s]:%hu => [%s]:%hu proto=%d ts=%u\n",
		       i, rem_host, rem_port, int_client, int_port, proto, timestamp);
		printf("    desc='%s'\n", desc);
		printf("    packets=%" PRIu64 "\n", packets);
	}
}
#endif

int main(int argc, char * *argv)
{
#ifndef ENABLE_IPV6
	fprintf(stderr,"nothing to test, ENABLE_IPV6 is not defined in config.h\n");
	return 1;
#else
	int ret;
	(void)argc; (void)argv;

	openlog("testpfpinhole", LOG_PERROR, LOG_USER);
	if(init_redirect() < 0) {
		fprintf(stderr, "init_redirect() failed\n");
		return 1;
	}

	ret = add_pinhole_rule("ep0", "2001::1:2:3", 12345, "123::ff", 54321, IPPROTO_UDP, "description test 1", 424242);
	printf("add_pinhole_rule() returned %d\n", ret);
	ret = add_pinhole_rule("ep0", NULL, 0, "dead:beef::42:42", 8080, IPPROTO_UDP, "description test 2", 4321000);
	printf("add_pinhole_rule() returned %d\n", ret);

	print_pinholes();
	clean_pinhole_list(NULL);

	ret = delete_pinhole_rule("2001::1:2:3", 12345, "123::ff", 54321, IPPROTO_UDP);
	printf("delete_pinhole_rule() returned %d\n", ret);
	ret = delete_pinhole_rule(NULL, 0, "dead:beef::42:42", 8080, IPPROTO_UDP);
	printf("delete_pinhole_rule() returned %d\n", ret);
#endif
	return 0;
}
