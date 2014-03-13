/* $Id $ */
/* MiniUPnP project
 * (c) 2007-2014 Thomas Bernard
 * http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "macros.h"
#include "config.h"
#include "upnpglobalvars.h"
#include "getifaddr.h"
#include "portinuse.h"

#if defined(USE_NETFILTER)
#include "netfilter/iptcrdr.h"
#endif

#ifdef CHECK_PORTINUSE

#if defined(USE_NETFILTER)
/* Hardcoded for now.  Ideally would come from .conf file */
char *chains_to_check[] = { "PREROUTING" , 0 };
#endif

int port_in_use(const char *if_name, unsigned eport, int proto, const char *iaddr, unsigned iport)
{
	char line[256];
	FILE *f;
	int found = 0;
	char ip_addr_str[INET_ADDRSTRLEN];
	struct in_addr ip_addr;
	const char tcpfile[] = "/proc/net/tcp";
	const char udpfile[] = "/proc/net/udp";

	f = fopen((proto==IPPROTO_TCP)?tcpfile:udpfile, "r");
	if (!f) return 0;

	if(getifaddr(if_name, ip_addr_str, INET_ADDRSTRLEN, &ip_addr, NULL) < 0)
		ip_addr.s_addr = 0;

	syslog(LOG_DEBUG, "Check protocol %s for port %d on ext_if %s %s, %8X",
		(proto==IPPROTO_TCP)?"tcp":"udp", eport, if_name, ip_addr_str, (unsigned)ip_addr.s_addr);

	while (fgets(line, 255, f)) {
		char eaddr[68];
		unsigned tmp_port;
		if (sscanf(line, "%*d: %64[0-9A-Fa-f]:%x %*x:%*x %*x %*x:%*x "
				"%*x:%*x %*x %*d %*d %*llu",
				eaddr, &tmp_port) == 2
		) {
			/* TODO add IPV6 support if enabled
			 * Presently assumes IPV4 */
			// syslog(LOG_DEBUG, "port_in_use check port %d and address %s", tmp_port, eaddr);
			if (tmp_port == eport) {
				char tmp_addr[4];
				struct in_addr *tmp_ip_addr = (struct in_addr *)tmp_addr;
				if (sscanf(eaddr,"%2hhx%2hhx%2hhx%2hhx",
					&tmp_addr[3],&tmp_addr[2],&tmp_addr[1],&tmp_addr[0]) == 4)
				{
					if (tmp_ip_addr->s_addr == 0 || tmp_ip_addr->s_addr == ip_addr.s_addr)
					{
						found++;
						break;  /* don't care how many, just that we found at least one */
					}
				}
			}
		}
	}
	fclose(f);

#if defined(USE_NETFILTER)
	if (!found) {
		char iaddr_old[16];
		unsigned short iport_old;
		int i = 0;
		while (chains_to_check[i]) {
			if (get_nat_redirect_rule(chains_to_check[i], if_name, eport, proto,
					iaddr_old, sizeof(iaddr_old), &iport_old,
					0, 0, 0, 0, 0, 0, 0) == 0)
			{
				syslog(LOG_DEBUG, "port_in_use check port %d on nat chain %s redirected to %s port %d", eport,
						chains_to_check[i], iaddr_old, iport_old);
				if (!(strcmp(iaddr, iaddr_old)==0 && iport==iport_old)) {
					/* only "in use" if redirected to somewhere else */
					found++;
					break;  /* don't care how many, just that we found at least one */
				}
			}
			i++;
		}
	}
#endif /* USE_NETFILTER */
	return found;
}
#endif /* CHECK_PORTINUSE */
