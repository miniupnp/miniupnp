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
#if defined(__OpenBSD__)
#include <sys/queue.h>
#include <kvm.h>
#include <fcntl.h>
#include <nlist.h>
#include <limits.h>
#include <net/route.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
/*
#include <netinet/tcp.h>
#include <netinet/tcpip.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_var.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
*/
#endif

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

int
port_in_use(const char *if_name,
            unsigned eport, int proto,
            const char *iaddr, unsigned iport)
{
	int found = 0;
	char ip_addr_str[INET_ADDRSTRLEN];
	struct in_addr ip_addr;
#ifdef __linux__
	/* linux code */
	char line[256];
	FILE *f;
	const char * tcpfile = "/proc/net/tcp";
	const char * udpfile = "/proc/net/udp";
#endif

	if(getifaddr(if_name, ip_addr_str, INET_ADDRSTRLEN, &ip_addr, NULL) < 0)
		ip_addr.s_addr = 0;

	syslog(LOG_DEBUG, "Check protocol %s for port %d on ext_if %s %s, %08X",
		(proto==IPPROTO_TCP)?"tcp":"udp", eport, if_name, ip_addr_str, (unsigned)ip_addr.s_addr);

#ifdef __linux__
	f = fopen((proto==IPPROTO_TCP)?tcpfile:udpfile, "r");
	if (!f) {
		syslog(LOG_ERR, "cannot open %s", (proto==IPPROTO_TCP)?tcpfile:udpfile);
		return 0;
	}

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
#endif /* __linux__ */

#if defined(__OpenBSD__)
static struct nlist list[] = {
#if 0
        {"_tcpstat", 0, 0, 0, 0},
        {"_udpstat", 0, 0, 0, 0},
        {"_tcbinfo", 0, 0, 0, 0},
        {"_udbinfo", 0, 0, 0, 0},
#endif
		{"_tcbtable", 0, 0, 0, 0},
		{"_udbtable", 0, 0, 0, 0},
        {NULL,0, 0, 0, 0}
};
	char errstr[_POSIX2_LINE_MAX];
	kvm_t *kd;
	ssize_t n;
	struct inpcbtable table;
	struct inpcb *next;
	struct inpcb inpcb;
	kd = kvm_openfiles(NULL, NULL, NULL, O_RDONLY, errstr);
	if(!kd) {
		syslog(LOG_ERR, "portinuse(): kvm_openfiles(): %s", errstr);
		return -1;
	}
	if(kvm_nlist(kd, list) < 0) {
		syslog(LOG_ERR, "portinuse(): kvm_nlist(): %s", kvm_geterr(kd));
		kvm_close(kd);
		return -1;
	}
	n = kvm_read(kd, list[(proto==IPPROTO_TCP)?0:1].n_value, &table, sizeof(table));
	if(n < 0) {
		syslog(LOG_ERR, "kvm_read(): %s", kvm_geterr(kd));
		kvm_close(kd);
		return -1;
	}
	next = CIRCLEQ_FIRST(&table.inpt_queue);	/*TAILQ_FIRST(&table.inpt_queue);*/
	while(next != NULL) {
		/* syslog(LOG_DEBUG, "next=0x%08lx", (u_long)next); */
		if(((u_long)next & 3) != 0) break;
		n = kvm_read(kd, (u_long)next, &inpcb, sizeof(inpcb));
		if(n < 0) {
			syslog(LOG_ERR, "kvm_read(): %s", kvm_geterr(kd));
			break;
		}
		next = CIRCLEQ_NEXT(&inpcb, inp_queue);	/*TAILQ_NEXT(&inpcb, inp_queue);*/
		if((inpcb.inp_flags & INP_IPV6) != 0)
			continue;
		syslog(LOG_DEBUG, "%08lx:%hu %08lx:%hu",
		       (u_long)inpcb.inp_laddr.s_addr, ntohs(inpcb.inp_lport),
		       (u_long)inpcb.inp_faddr.s_addr, ntohs(inpcb.inp_fport));
		if(eport == (unsigned)ntohs(inpcb.inp_lport)) {
			if(inpcb.inp_laddr.s_addr == INADDR_ANY || inpcb.inp_laddr.s_addr == ip_addr.s_addr) {
				found++;
				break;  /* don't care how many, just that we found at least one */
			}
		}
	}
	kvm_close(kd);
#endif


#if defined(USE_NETFILTER)
	if (!found) {
		char iaddr_old[16];
		unsigned short iport_old;
		int i;
		for (i = 0; chains_to_check[i]; i++) {
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
		}
	}
#else /* USE_NETFILTER */
	UNUSED(iport); UNUSED(iaddr);
#endif /* USE_NETFILTER */
	return found;
}
#endif /* CHECK_PORTINUSE */
