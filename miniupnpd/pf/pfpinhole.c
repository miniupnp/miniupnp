/* $Id: pfpinhole.c,v 1.30 2024/01/14 23:56:45 nanard Exp $ */
/* vim: tabstop=4 shiftwidth=4 noexpandtab
 * MiniUPnP project
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * (c) 2012-2024 Thomas Bernard
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

#include "config.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#ifdef __DragonFly__
#include <net/pf/pfvar.h>
#else
#ifdef __APPLE__
#define PRIVATE 1
#endif
#include <net/pfvar.h>
#endif
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef USE_LIBPFCTL
#include <libpfctl.h>
#endif

#include "pfpinhole.h"
#include "../upnpglobalvars.h"
#include "../macros.h"
#include "../upnputils.h"
#include "rtickets.h"

/* the pass rules created by add_map6_rule() are as follow :
 *
 * pass in quick on ep0 inet6 proto udp
 *   from any to dead:beef::42:42 port = 8080
 *   flags S/SA keep state
 *
 * A rule is found by its addresses, ports and protocol. It holds no label:
 * no uid or expiry, which are the map's.
 */

#ifdef ENABLE_UPNPPINHOLE

/* /dev/pf when opened */
extern int dev;



/* 1 if RULE is the map6 rule of the key, as key_addrs() parsed it. The
 * IPv6 pass rules of the anchor are the map6 rules: they hold no label */
#define RULE_IS_PINHOLE_OF(saddr, rport, daddr, iport, proto) \
	((proto) == RULE.proto && (rport) == ntohs(RULE.src.port[0]) && \
	 (iport) == ntohs(RULE.dst.port[0]) && \
	 0 == memcmp(&(saddr), &RULE.src.addr.v.a.addr.v6, sizeof(struct in6_addr)) && \
	 0 == memcmp(&(daddr), &RULE.dst.addr.v.a.addr.v6, sizeof(struct in6_addr)) && \
	 RULE.af == AF_INET6)

/* the addresses of a key. 0, or -1 if one does not parse */
static int
key_addrs(const char * rem_host, const char * int_client,
          struct in6_addr * saddr, struct in6_addr * daddr)
{
	memset(saddr, 0, sizeof(*saddr));
	if(!map6_any_remote(rem_host) && inet_pton(AF_INET6, rem_host, saddr) != 1) {
		syslog(LOG_ERR, "inet_pton(%s) failed", rem_host);
		return -1;
	}
	if(int_client == NULL || inet_pton(AF_INET6, int_client, daddr) != 1) {
		syslog(LOG_ERR, "inet_pton(%s) failed", int_client ? int_client : "(null)");
		return -1;
	}
	return 0;
}

#define RULE (pr.rule)

int add_map6_rule(const char * ifname,
                     const char * rem_host, unsigned short rem_port,
                     const char * int_client, unsigned short int_port,
                     int proto, const char * desc, unsigned int timestamp)
{
	struct pfioc_rule pr;
#ifndef PF_NEWSTYLE
	struct pfioc_pooladdr pp;
#endif

	UNUSED(desc);		/* the map holds the description */
	UNUSED(timestamp);	/* and the expiry */
	if(dev<0) {
		syslog(LOG_ERR, "pf device is not open");
		return -1;
	}
	memset(&pr, 0, sizeof(pr));
	strlcpy(pr.anchor, anchor_name, MAXPATHLEN);

#ifndef PF_NEWSTYLE
	memset(&pp, 0, sizeof(pp));
	strlcpy(pp.anchor, anchor_name, MAXPATHLEN);
	if(ioctl(dev, DIOCBEGINADDRS, &pp) < 0) {
		syslog(LOG_ERR, "ioctl(dev, DIOCBEGINADDRS, ...): %m");
		return -1;
	} else {
		pr.pool_ticket = pp.ticket;
#else
	{
#endif
		RULE.direction = PF_IN;
		RULE.action = PF_PASS;
		RULE.af = AF_INET6;
#ifdef PF_NEWSTYLE
		RULE.nat.addr.type = PF_ADDR_NONE;
		RULE.rdr.addr.type = PF_ADDR_NONE;
#endif
#ifdef USE_IFNAME_IN_RULES
		if(ifname)
			strlcpy(RULE.ifname, ifname, IFNAMSIZ);
#endif
		RULE.proto = proto;

		RULE.quick = 1;/*(GETFLAG(PFNOQUICKRULESMASK))?0:1;*/
		RULE.log = (GETFLAG(LOGPACKETSMASK))?1:0;	/*logpackets;*/
/* see the discussion on the forum :
 * http://miniupnp.tuxfamily.org/forum/viewtopic.php?p=638 */
		RULE.flags = TH_SYN;
		RULE.flagset = (TH_SYN|TH_ACK);
#ifdef PFRULE_HAS_RTABLEID
		RULE.rtableid = -1;	/* first appeared in OpenBSD 4.0 */
#endif
#ifdef PFRULE_HAS_ONRDOMAIN
		RULE.onrdomain = -1;	/* first appeared in OpenBSD 5.0 */
#endif
		RULE.keep_state = 1;
		if(queue)
			strlcpy(RULE.qname, queue, PF_QNAME_SIZE);
		if(tag)
			strlcpy(RULE.tagname, tag, PF_TAG_NAME_SIZE);

		if(rem_port) {
			RULE.src.port_op = PF_OP_EQ;
			RULE.src.port[0] = htons(rem_port);
		}
		if(!map6_any_remote(rem_host)) {
			RULE.src.addr.type = PF_ADDR_ADDRMASK;
			if(inet_pton(AF_INET6, rem_host, &RULE.src.addr.v.a.addr.v6) != 1) {
				syslog(LOG_ERR, "inet_pton(%s) failed", rem_host);
			}
			memset(&RULE.src.addr.v.a.mask.addr8, 255, 16);
		}

		RULE.dst.port_op = PF_OP_EQ;
		RULE.dst.port[0] = htons(int_port);
		RULE.dst.addr.type = PF_ADDR_ADDRMASK;
		if(inet_pton(AF_INET6, int_client, &RULE.dst.addr.v.a.addr.v6) != 1) {
			syslog(LOG_ERR, "inet_pton(%s) failed", int_client);
		}
		memset(&RULE.dst.addr.v.a.mask.addr8, 255, 16);

		if(ifname)
			strlcpy(RULE.ifname, ifname, IFNAMSIZ);

		pr.action = PF_CHANGE_GET_TICKET;
		if(ioctl(dev, DIOCCHANGERULE, &pr) < 0) {
			syslog(LOG_ERR, "ioctl(dev, DIOCCHANGERULE, ...) PF_CHANGE_GET_TICKET: %m");
			return -1;
		} else {
			pr.action = PF_CHANGE_ADD_TAIL;
			if(ioctl(dev, DIOCCHANGERULE, &pr) < 0) {
				syslog(LOG_ERR, "ioctl(dev, DIOCCHANGERULE, ...) PF_CHANGE_ADD_TAIL: %m");
				return -1;
			}
		}
	}

	return 0;
}

int get_map6_packets(const char * rem_host, unsigned short rem_port,
                        const char * int_client, unsigned short int_port,
                        int proto, u_int64_t * packets)
{
	unsigned int tnum;
	int i, n;
#undef RULE
#ifdef USE_LIBPFCTL
	struct pfctl_rules_info ri;
	struct pfctl_rule rule;
#define RULE (rule)
	char anchor_call[MAXPATHLEN] = "";
#else /* USE_LIBPFCTL */
	struct pfioc_rule pr;
#define RULE (pr.rule)
#endif /* USE_LIBPFCTL */
	struct in6_addr saddr;
	struct in6_addr daddr;

	if(dev<0) {
		syslog(LOG_ERR, "pf device is not open");
		return -1;
	}
	if(key_addrs(rem_host, int_client, &saddr, &daddr) < 0)
		return -1;
#ifdef USE_LIBPFCTL
	if((errno = pfctl_get_rules_info(dev, &ri, PF_PASS, anchor_name)) != 0)
	{
		syslog(LOG_ERR, "pfctl_get_rules_info: %m");
		return -1;
	}
	n = ri.nr;
#ifdef PF_RELEASETICKETS
	tnum = ri.ticket;
#endif /* PF_RELEASETICKETS */
#else /* USE_LIBPFCTL */
	memset(&pr, 0, sizeof(pr));
	strlcpy(pr.anchor, anchor_name, MAXPATHLEN);
#ifndef PF_NEWSTYLE
	RULE.action = PF_PASS;
#endif
	if(ioctl(dev, DIOCGETRULES, &pr) < 0) {
		syslog(LOG_ERR, "ioctl(dev, DIOCGETRULES, ...): %m");
		return -1;
	}
	n = pr.nr;
#ifdef PF_RELEASETICKETS
	tnum = pr.ticket;
#endif /* PF_RELEASETICKETS */
#endif /* USE_LIBPFCTL */
	for(i=0; i<n; i++) {
#ifdef USE_LIBPFCTL
		if((errno = pfctl_get_rule(dev, i, ri.ticket, anchor_name, PF_PASS, &rule, anchor_call)) != 0)
		{
			syslog(LOG_ERR, "pfctl_get_rule: %m");
			release_ticket(dev, tnum);
			return -1;
		}
#else /* USE_LIBPFCTL */
		pr.nr = i;
		if(ioctl(dev, DIOCGETRULE, &pr) < 0) {
			syslog(LOG_ERR, "ioctl(dev, DIOCGETRULE): %m");
			release_ticket(dev, tnum);
			return -1;
		}
#endif /* USE_LIBPFCTL */
		if(RULE_IS_PINHOLE_OF(saddr, rem_port, daddr, int_port, proto)) {
#ifdef PFRULE_INOUT_COUNTS
			if(packets)
				*packets = RULE.packets[0] + RULE.packets[1];
#else
			if(packets)
				*packets = RULE.packets;
#endif
			release_ticket(dev, tnum);
			return 0;
		}
	}
	release_ticket(dev, tnum);
	return -2;
}

int delete_map6_rule(const char * rem_host, unsigned short rem_port,
                        const char * int_client, unsigned short int_port,
                        int proto)
{
	int i, n;
	unsigned int tnum;
	struct in6_addr saddr, daddr;
#undef RULE
#ifdef USE_LIBPFCTL
	struct pfctl_rules_info ri;
	struct pfctl_rule rule;
#define RULE (rule)
	char anchor_call[MAXPATHLEN] = "";
#else /* USE_LIBPFCTL */
	struct pfioc_rule pr;
#define RULE (pr.rule)
#endif /* USE_LIBPFCTL */

	if(dev<0) {
		syslog(LOG_ERR, "pf device is not open");
		return -1;
	}
	if(key_addrs(rem_host, int_client, &saddr, &daddr) < 0)
		return -1;
#ifdef USE_LIBPFCTL
	if((errno = pfctl_get_rules_info(dev, &ri, PF_PASS, anchor_name)) != 0)
	{
		syslog(LOG_ERR, "pfctl_get_rules_info: %m");
		return -1;
	}
	n = ri.nr;
#ifdef PF_RELEASETICKETS
	tnum = ri.ticket;
#endif /* PF_RELEASETICKETS */
#else /* USE_LIBPFCTL */
	memset(&pr, 0, sizeof(pr));
	strlcpy(pr.anchor, anchor_name, MAXPATHLEN);
#ifndef PF_NEWSTYLE
	RULE.action = PF_PASS;
#endif
	if(ioctl(dev, DIOCGETRULES, &pr) < 0) {
		syslog(LOG_ERR, "ioctl(dev, DIOCGETRULES, ...): %m");
		return -1;
	}
	n = pr.nr;
#ifdef PF_RELEASETICKETS
	tnum = pr.ticket;
#endif
#endif /* USE_LIBPFCTL */
	for(i=0; i<n; i++) {
#ifdef USE_LIBPFCTL
		if((errno = pfctl_get_rule(dev, i, ri.ticket, anchor_name, PF_PASS, &rule, anchor_call)) != 0)
		{
			syslog(LOG_ERR, "pfctl_get_rule: %m");
			return -1;
		}
#else /* USE_LIBPFCTL */
		pr.nr = i;
		if(ioctl(dev, DIOCGETRULE, &pr) < 0) {
			syslog(LOG_ERR, "ioctl(dev, DIOCGETRULE): %m");
			return -1;
		}
#endif /* USE_LIBPFCTL */
		if(RULE_IS_PINHOLE_OF(saddr, rem_port, daddr, int_port, proto)) {
#ifdef USE_LIBPFCTL
			/* TODO: convert DIOCCHANGERULE to libpfctl */
			struct pfioc_rule pr;
			memset(&pr, 0, sizeof(pr));
			pr.action = PF_CHANGE_GET_TICKET;
			pr.ticket = ri.ticket;
			pr.nr = i;
			strlcpy(pr.anchor, anchor_name, MAXPATHLEN);
#else /* USE_LIBPFCTL */
			pr.action = PF_CHANGE_GET_TICKET;
#endif /* USE_LIBPFCTL */
			if(ioctl(dev, DIOCCHANGERULE, &pr) < 0) {
				syslog(LOG_ERR, "ioctl(dev, DIOCCHANGERULE, ...) PF_CHANGE_GET_TICKET: %m");
				release_ticket(dev, tnum);
				return -1;
			}
			pr.action = PF_CHANGE_REMOVE;
			pr.nr = i;
			if(ioctl(dev, DIOCCHANGERULE, &pr) < 0) {
				syslog(LOG_ERR, "ioctl(dev, DIOCCHANGERULE, ...) PF_CHANGE_REMOVE: %m");
				release_ticket(dev, tnum);
				return -1;
			}
			release_ticket(dev, tnum);
			return 0;
		}
	}
	release_ticket(dev, tnum);
	/* not found */
	return -2;
}

int
get_map6_rule_at(int index, char * rem_host, int rem_hostlen,
                    unsigned short * rem_port,
                    char * int_client, int int_clientlen,
                    unsigned short * int_port, int * proto,
                    char * desc, int desclen)
{
	int i, n;
	unsigned int tnum;
	static const struct in6_addr any;
#undef RULE
#ifdef USE_LIBPFCTL
	struct pfctl_rules_info ri;
	struct pfctl_rule rule;
#define RULE (rule)
	char anchor_call[MAXPATHLEN] = "";
#else /* USE_LIBPFCTL */
	struct pfioc_rule pr;
#define RULE (pr.rule)
#endif /* USE_LIBPFCTL */

	if(dev<0) {
		syslog(LOG_ERR, "pf device is not open");
		return -1;
	}
#ifdef USE_LIBPFCTL
	if((errno = pfctl_get_rules_info(dev, &ri, PF_PASS, anchor_name)) != 0)
	{
		syslog(LOG_ERR, "pfctl_get_rules_info: %m");
		return -1;
	}
	n = ri.nr;
#ifdef PF_RELEASETICKETS
	tnum = ri.ticket;
#endif /* PF_RELEASETICKETS */
#else /* USE_LIBPFCTL */
	memset(&pr, 0, sizeof(pr));
	strlcpy(pr.anchor, anchor_name, MAXPATHLEN);
#ifndef PF_NEWSTYLE
	RULE.action = PF_PASS;
#endif
	if(ioctl(dev, DIOCGETRULES, &pr) < 0) {
		syslog(LOG_ERR, "ioctl(dev, DIOCGETRULES, ...): %m");
		return -1;
	}
	n = pr.nr;
#ifdef PF_RELEASETICKETS
	tnum = pr.ticket;
#endif
#endif /* USE_LIBPFCTL */
	for(i=0; i<n; i++) {
#ifdef USE_LIBPFCTL
		if((errno = pfctl_get_rule(dev, i, ri.ticket, anchor_name, PF_PASS, &rule, anchor_call)) != 0)
		{
			syslog(LOG_ERR, "pfctl_get_rule: %m");
			release_ticket(dev, tnum);
			return -1;
		}
#else /* USE_LIBPFCTL */
		pr.nr = i;
		if(ioctl(dev, DIOCGETRULE, &pr) < 0) {
			syslog(LOG_ERR, "ioctl(dev, DIOCGETRULE): %m");
			release_ticket(dev, tnum);
			return -1;
		}
#endif /* USE_LIBPFCTL */
		if(RULE.af != AF_INET6 || index-- > 0)
			continue;
		if(rem_host && rem_hostlen > 0) {
			rem_host[0] = '\0';
			if(memcmp(&RULE.src.addr.v.a.addr.v6, &any, sizeof(any)) != 0)
				inet_ntop(AF_INET6, &RULE.src.addr.v.a.addr.v6, rem_host, rem_hostlen);
		}
		if(rem_port)
			*rem_port = ntohs(RULE.src.port[0]);
		if(int_client && (inet_ntop(AF_INET6, &RULE.dst.addr.v.a.addr.v6, int_client, int_clientlen) == NULL)) {
			release_ticket(dev, tnum);
			return -1;
		}
		if(int_port)
			*int_port = ntohs(RULE.dst.port[0]);
		if(proto)
			*proto = RULE.proto;
		if(desc && desclen > 0)
			desc[0] = '\0';	/* the rule holds none */
		release_ticket(dev, tnum);
		return 0;
	}
	release_ticket(dev, tnum);
	/* past the end */
	return -1;
}

/* The rule holds neither the description nor the expiry, so an update has
 * nothing to change in it, and keeps its counters: it only checks that the
 * rule is there. */
int update_map6_rule(const char * ifname,
                        const char * rem_host, unsigned short rem_port,
                        const char * int_client, unsigned short int_port,
                        int proto, const char * desc, unsigned int timestamp)
{
	UNUSED(ifname); UNUSED(desc); UNUSED(timestamp);
	return get_map6_packets(rem_host, rem_port, int_client, int_port, proto, NULL);
}

#endif /* ENABLE_UPNPPINHOLE */
