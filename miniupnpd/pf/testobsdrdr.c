/* $Id: testobsdrdr.c,v 1.32 2024/06/22 16:48:54 nanard Exp $ */
/* MiniUPnP project
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * (c) 2006-2024 Thomas Bernard
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <syslog.h>

#include "obsdrdr.h"

/*int logpackets = 1;*/
int runtime_flags = 0;
const char * tag = 0;
const char * anchor_name = "miniupnpd";
const char * queue = NULL;
const char * use_ext_ip_addr = "42.42.42.42";

void
list_rules(void);

void
test_index(void)
{
	char ifname[16/*IFNAMSIZ*/];
	char iaddr[32];
	char rhost[32];
	unsigned short iport = 0;
	unsigned short eport = 0;
	int proto = 0;
	ifname[0] = '\0';
	iaddr[0] = '\0';
	rhost[0] = '\0';
	if(get_redirect_rule_by_index(0, ifname, &eport, iaddr, sizeof(iaddr),
	                              &iport, &proto,
	                              rhost, sizeof(rhost), 0, 0) < 0)
	{
		printf("get.._by_index : no rule\n");
	}
	else
	{
		printf("%s %u -> %s:%u proto %d\n", ifname, (unsigned int)eport,
		       iaddr, (unsigned int)iport, proto);
	}
}

int
main(int argc, char * * argv)
{
	char buf[32];
	char rhost[64];
	/*char rhost[32];*/
	unsigned short iport;
	u_int64_t packets = 0;
	u_int64_t bytes = 0;
	int clear = 0;

	if(argc > 1) {
		if(0 == strcmp(argv[1], "--clear") || 0 == strcmp(argv[1], "-c"))
			clear = 1;
	}

	openlog("testobsdrdr", LOG_PERROR, LOG_USER);
	if(init_redirect() < 0)
	{
		fprintf(stderr, "init_redirect() failed\n");
		return 1;
	}
#if 0
	add_redirect_rule("ep0", 12123, "192.168.1.23", 1234);
	add_redirect_rule2("ep0", 12155, "192.168.1.155", 1255, IPPROTO_TCP);
#endif
	if(add_redirect_rule2("ep0", NULL/*"8.8.8.8"*/, 12123, "192.168.1.125", 1234,
	                   IPPROTO_UDP) < 0)
		printf("add_redirect_rule2() #3 failed\n");
	use_ext_ip_addr = NULL;
	if(add_redirect_rule2("em0", NULL, 12123, "127.1.2.3", 1234,
	                   IPPROTO_TCP) < 0)
		printf("add_redirect_rule2() #4 failed\n");
	if(add_filter_rule2("em0", NULL, "127.1.2.3", 12123, 1234, IPPROTO_TCP) < 0)
		printf("add_filter_rule2() #1 failed\n");

	list_rules();


	if(get_redirect_rule("xl1", 4662, IPPROTO_TCP,
	                     buf, sizeof(buf), &iport,
	                     rhost, sizeof(rhost),
	                     &packets, &bytes) < 0)
		printf("get_redirect_rule() failed\n");
	else
	{
		printf("\n%s:%d packets=%" PRIu64 " bytes=%" PRIu64 "\n", buf, (int)iport,
		       packets, bytes);
	}

/*
	if(delete_redirect_rule("ep0", 12123, IPPROTO_UDP) < 0)
		printf("delete_redirect_rule() failed\n");
*/
	if(delete_redirect_and_filter_rules("ep0", 12123, IPPROTO_UDP) < 0)
		printf("delete_redirect_and_filter_rules() failed\n");

	if(delete_redirect_rule("ep0", 12123, IPPROTO_UDP) < 0)
		printf("delete_redirect_rule() failed\n");

	if(delete_redirect_and_filter_rules("em0", 12123, IPPROTO_TCP) < 0)
		printf("delete_redirect_and_filter_rules() failed\n");

	test_index();

	if(clear) {
		clear_redirect_rules();
		clear_filter_rules();
		clear_nat_rules();
	}
	/*list_rules();*/

	return 0;
}


