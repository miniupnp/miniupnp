/* $Id: $ */
/* vim: tabstop=4 shiftwidth=4 noexpandtab
 * MiniUPnP project
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * (c) 2020-2025 Thomas Bernard
 * (c) 2018 Pali Rohár
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <time.h>

#include "config.h"
#include "upnpglobalvars.h"
#include "upnpstun.h"

struct lan_addr_list lan_addrs;
int runtime_flags = 0;
time_t startup_time = 0;
const char * use_ext_ip_addr = 0;
const char * tag = 0;
const char * anchor_name = "miniupnpd";

int main(int argc, char *argv[])
{
	struct in_addr ext_addr;
	int restrictive_nat;
	int ret;
	char str[INET_ADDRSTRLEN];
	const char * host;
	unsigned short port = 0;

	if (argc != 3 && argc != 2) {
		printf("Usage: %s stun_host [stun_port]\n", argv[0]);
		return 1;
	}

	if (geteuid() != 0) {
		fprintf(stderr, "You may need to run this application as root\n");
	}

	host = argv[1];
	if (argc > 2) {
		port = (unsigned short)atoi(argv[2]);
	}

	openlog("teststun", LOG_CONS|LOG_PERROR, LOG_USER);

	srandom(time(NULL) * getpid());

	ret = perform_stun(NULL, NULL, host, port, &ext_addr, &restrictive_nat);
	if (ret != 0) {
		printf("STUN Failed: %s\n", strerror(errno));
		return 1;
	}

	if (!inet_ntop(AF_INET, &ext_addr, str, INET_ADDRSTRLEN))
		str[0] = 0;

	printf("External IP address: %s\n", str);
	printf("Restrictive NAT: %s\n", restrictive_nat ? "active (port forwarding impossible)" : "not used (ready for port forwarding)");
	return 0;
}
