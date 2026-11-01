/* $Id: obsdrdr.c,v 1.102 2023/12/07 18:56:32 nanard Exp $ */
/* vim: tabstop=4 shiftwidth=4 noexpandtab
 * MiniUPnP project
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * (c) 2006-2025 Thomas Bernard
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

/*
 * pf rules created (with ext_if = xl1)
 * - OpenBSD up to version 4.6 :
 *     rdr pass on xl1 inet proto udp from any to any port = 54321 \
 *         keep state label "test label" -> 192.168.0.42 port 12345
 *   or a rdr rule + a pass rule :
 *     rdr quick on xl1 inet proto udp from any to any port = 54321 \
 *         keep state label "test label" -> 192.168.0.42 port 12345
 *     pass in quick on xl1 inet proto udp from any to 192.168.0.42 port = 12345 \
 *          flags S/SA keep state label "test label"
 *
 * - OpenBSD starting from version 4.7
 *     match in on xl1 inet proto udp from any to any port 54321 \
 *            label "test label" rdr-to 192.168.0.42 port 12345
 *   or
 *     pass in quick on xl1 inet proto udp from any to any port 54321 \
 *            label "test label" rdr-to 192.168.0.42 port 12345
 *
 *
 *
 * Macros/#defines :
 * - PF_ENABLE_FILTER_RULES
 *   If set, two rules are created : rdr + pass. Else a rdr/pass rule
 *   is created.
 * - USE_IFNAME_IN_RULES
 *   If set the interface name is set in the rule.
 * - PFRULE_INOUT_COUNTS
 *   Must be set with OpenBSD version 3.8 and up, FreeBSD 7.0+, DragonFly 2.8+
 *   and OS X with pf.
 * - PFRULE_HAS_RTABLEID
 *   Must be set with OpenBSD version 4.0 and up.
 * - PF_NEWSTYLE
 *   Must be set with OpenBSD version 4.7 and up. FreeBSD/pfSense is old style.
 * - USE_LIBPFCTL
 *   libpfctl was introduced in FreeBSD 14. Starting with FreeBSD 15,
 *   several ioctl calls (such as DIOCGETRULE) are removed, so libpfctl has
 *   to be used.
 */

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
#include <stdio.h>
#include <stdlib.h>
#ifdef USE_LIBPFCTL
#include <libpfctl.h>
#endif

#include "../macros.h"
#include "obsdrdr.h"
#include "../upnpglobalvars.h"
#include "../getifaddr.h"
#include "rtickets.h"
#include "../pcp_filter.h"

#ifndef USE_PF
#error "USE_PF macro is undefined, check consistency between config.h and Makefile"
#else

/* list to keep timestamps for port mappings having a lease duration */
struct timestamp_entry {
	struct timestamp_entry * next;
	unsigned int timestamp;
	unsigned short eport;
	short protocol;
};

static struct timestamp_entry * timestamp_list = NULL;

static unsigned int
get_timestamp(unsigned short eport, int proto)
{
	struct timestamp_entry * e;
	e = timestamp_list;
	while(e) {
		if(e->eport == eport && e->protocol == (short)proto)
			return e->timestamp;
		e = e->next;
	}
	return 0;
}

static void
remove_timestamp_entry(unsigned short eport, int proto)
{
	struct timestamp_entry * e;
	struct timestamp_entry * * p;
	p = &timestamp_list;
	e = *p;
	while(e) {
		if(e->eport == eport && e->protocol == (short)proto) {
			/* remove the entry */
			*p = e->next;
			free(e);
			return;
		}
		p = &(e->next);
		e = *p;
	}
}

static void
add_timestamp_entry(unsigned short eport, int proto, unsigned timestamp)
{
	struct timestamp_entry * tmp;
	tmp = malloc(sizeof(struct timestamp_entry));
	if(tmp)
	{
		tmp->next = timestamp_list;
		tmp->timestamp = timestamp;
		tmp->eport = eport;
		tmp->protocol = (short)proto;
		timestamp_list = tmp;
	}
	else
	{
		syslog(LOG_ERR, "add_timestamp_entry() malloc(%lu) error",
		       sizeof(struct timestamp_entry));
	}
}

/* /dev/pf when opened */
extern int dev;	/* global also used in pfpinhole.c */
int dev = -1;

#ifdef PCP_PEER
static void free_peer_leases(void);
#endif

/* shutdown_redirect() :
 * close the /dev/pf device */
void
shutdown_redirect(void)
{
	if(close(dev)<0)
		syslog(LOG_ERR, "close(\"/dev/pf\"): %m");
	dev = -1;
#ifdef PCP_PEER
	free_peer_leases();
#endif
}

/* open the device */
int
init_redirect(void)
{
#ifdef USE_LIBPFCTL
	struct pfctl_status *status;
#else
	struct pf_status status;
#endif
	if(dev>=0)
		shutdown_redirect();
	dev = open("/dev/pf", O_RDWR);
	if(dev<0) {
		syslog(LOG_ERR, "open(\"/dev/pf\"): %m");
		return -1;
	}
#ifdef USE_LIBPFCTL
	status = pfctl_get_status(dev);
	if (status == NULL) {
		syslog(LOG_ERR, "pfctl_get_status: %m");
		return -1;
	}
	if(!status->running) {
		pfctl_free_status(status);
		syslog(LOG_ERR, "pf is disabled");
		return -1;
	}
	pfctl_free_status(status);
#else
	if(ioctl(dev, DIOCGETSTATUS, &status)<0) {
		syslog(LOG_ERR, "DIOCGETSTATUS: %m");
		return -1;
	}
	if(!status.running) {
		syslog(LOG_ERR, "pf is disabled");
		return -1;
	}
#endif
	return 0;
}

#if TEST
/* for debug */
int
clear_redirect_rules(void)
{
	struct pfioc_trans io;
	struct pfioc_trans_e ioe;
	if(dev<0) {
		syslog(LOG_ERR, "pf device is not open");
		return -1;
	}
	memset(&ioe, 0, sizeof(ioe));
	io.size = 1;
	io.esize = sizeof(ioe);
	io.array = &ioe;
#ifndef PF_NEWSTYLE
	ioe.rs_num = PF_RULESET_RDR;
#else
	ioe.type = PF_TRANS_RULESET;
#endif
	strlcpy(ioe.anchor, anchor_name, MAXPATHLEN);
	if(ioctl(dev, DIOCXBEGIN, &io) < 0)
	{
		syslog(LOG_ERR, "ioctl(dev, DIOCXBEGIN, ...): %m");
		goto error;
	}
	if(ioctl(dev, DIOCXCOMMIT, &io) < 0)
	{
		syslog(LOG_ERR, "ioctl(dev, DIOCXCOMMIT, ...): %m");
		goto error;
	}
	return 0;
error:
	return -1;
}

int
clear_filter_rules(void)
{
#ifndef PF_ENABLE_FILTER_RULES
	return 0;
#else
	struct pfioc_trans io;
	struct pfioc_trans_e ioe;
	if(dev<0) {
		syslog(LOG_ERR, "pf device is not open");
		return -1;
	}
	memset(&ioe, 0, sizeof(ioe));
	io.size = 1;
	io.esize = sizeof(ioe);
	io.array = &ioe;
#ifndef PF_NEWSTYLE
	ioe.rs_num = PF_RULESET_FILTER;
#else
	/* ? */
	ioe.type = PF_TRANS_RULESET;
#endif
	strlcpy(ioe.anchor, anchor_name, MAXPATHLEN);
	if(ioctl(dev, DIOCXBEGIN, &io) < 0)
	{
		syslog(LOG_ERR, "ioctl(dev, DIOCXBEGIN, ...): %m");
		goto error;
	}
	if(ioctl(dev, DIOCXCOMMIT, &io) < 0)
	{
		syslog(LOG_ERR, "ioctl(dev, DIOCXCOMMIT, ...): %m");
		goto error;
	}
	return 0;
error:
	return -1;
#endif
}

int
clear_nat_rules(void)
{
	struct pfioc_trans io;
	struct pfioc_trans_e ioe;
	if(dev<0) {
		syslog(LOG_ERR, "pf device is not open");
		return -1;
	}
	memset(&ioe, 0, sizeof(ioe));
	io.size = 1;
	io.esize = sizeof(ioe);
	io.array = &ioe;
#ifndef PF_NEWSTYLE
	ioe.rs_num = PF_RULESET_NAT;
#else
	/* ? */
	ioe.type = PF_TRANS_RULESET;
#endif
	strlcpy(ioe.anchor, anchor_name, MAXPATHLEN);
	if(ioctl(dev, DIOCXBEGIN, &io) < 0)
	{
		syslog(LOG_ERR, "ioctl(dev, DIOCXBEGIN, ...): %m");
		goto error;
	}
	if(ioctl(dev, DIOCXCOMMIT, &io) < 0)
	{
		syslog(LOG_ERR, "ioctl(dev, DIOCXCOMMIT, ...): %m");
		goto error;
	}
	return 0;
error:
	return -1;
}
#endif

#if defined(ENABLE_PORT_TRIGGERING) || defined(PCP_PEER)
/* add_nat_rule_full()
 * nat on re0 inet proto udp from 192.168.1.49 port 3074 to any -> (re0) port 3148
 * <re0> is ext_if, (re0) is ext_ip
 * should be created when a port mapping (3148 => 192.168.1.49:3074 UDP) is created.
 * for symetric NAT / UPnP IGD NAT Port Triggering
 * If rport is not 0 the rule only matches that remote port (PCP PEER),
 * if extaddr_arg is not NULL it is used as the translated address. */
static int add_nat_rule_full(const char * ifname,
                 const char * rhost, unsigned short rport,
                 const char * extaddr_arg, unsigned short eport,
                 const char * iaddr, unsigned short iport, int proto,
                 const char * desc)
{
	int r;
	struct pfioc_rule pcr;
#ifndef PF_NEWSTYLE
	struct pfioc_pooladdr pp;
	struct pf_pooladdr *a;
#endif
	const char * extaddr;
	char extaddr_buf[INET_ADDRSTRLEN];
	struct in_addr wan_addr;

	if(dev<0) {
		syslog(LOG_ERR, "pf device is not open");
		return -1;
	}
	if(extaddr_arg && extaddr_arg[0] != '\0') {
		extaddr = extaddr_arg;
	} else if(getifaddr(ifname, extaddr_buf, INET_ADDRSTRLEN, &wan_addr, NULL) < 0) {
		syslog(LOG_WARNING, "failed to get address for interface %s", ifname);
		if(use_ext_ip_addr && use_ext_ip_addr[0] != '\0') {
			extaddr = use_ext_ip_addr;
		} else {
			return -1;	/* no address to use => failure */
		}
	} else {
		if (addr_is_reserved(&wan_addr)) {
			syslog(LOG_DEBUG, "WAN IP is reserved, it will be used for NAT");
			extaddr = extaddr_buf;
		} else if (use_ext_ip_addr && use_ext_ip_addr[0] != '\0') {
			extaddr = use_ext_ip_addr;
		} else {
			extaddr = extaddr_buf;
		}
	}
	syslog(LOG_DEBUG, "use external ip %s", extaddr);
	r = 0;
	memset(&pcr, 0, sizeof(pcr));
	strlcpy(pcr.anchor, anchor_name, MAXPATHLEN);

#ifndef PF_NEWSTYLE
	memset(&pp, 0, sizeof(pp));
	strlcpy(pp.anchor, anchor_name, MAXPATHLEN);
	if(ioctl(dev, DIOCBEGINADDRS, &pp) < 0)
	{
		syslog(LOG_ERR, "ioctl(dev, DIOCBEGINADDRS, ...): %m");
		r = -1;
	}
	else
	{
		pcr.pool_ticket = pp.ticket;
#else
	{
		pcr.rule.nat.addr.type = PF_ADDR_ADDRMASK;
		pcr.rule.rdr.addr.type = PF_ADDR_NONE;
#endif
		/*pcr.rule.src.addr.type = PF_ADDR_NONE;*/
		pcr.rule.src.addr.type = PF_ADDR_ADDRMASK;
		pcr.rule.dst.addr.type = PF_ADDR_ADDRMASK;

#ifndef PF_NEWSTYLE
		pcr.rule.action = PF_NAT;
#else
		pcr.rule.action = PF_PASS;	/* or PF_MATCH as we dont expect outbound packets to be blocked */
		pcr.rule.direction = PF_OUT;
#endif
		pcr.rule.af = AF_INET;
#ifdef USE_IFNAME_IN_RULES
		if(ifname)
			strlcpy(pcr.rule.ifname, ifname, IFNAMSIZ);
#endif
		pcr.rule.proto = proto;
		pcr.rule.log = (GETFLAG(LOGPACKETSMASK))?1:0;	/*logpackets;*/
#ifdef PFRULE_HAS_RTABLEID
		pcr.rule.rtableid = -1;	/* first appeared in OpenBSD 4.0 */
#endif
#ifdef PFRULE_HAS_ONRDOMAIN
		pcr.rule.onrdomain = -1;	/* first appeared in OpenBSD 5.0 */
#endif
		pcr.rule.quick = 1;
		pcr.rule.keep_state = PF_STATE_NORMAL;
		if(tag)
			strlcpy(pcr.rule.tagname, tag, PF_TAG_NAME_SIZE);
		strlcpy(pcr.rule.label, desc, PF_RULE_LABEL_SIZE);
#ifdef PFVAR_NEW_STYLE
		inet_pton(AF_INET, iaddr, &pcr.rule.src.addr.v.a.addr.v4addr.s_addr);
		pcr.rule.src.addr.v.a.mask.v4addr.s_addr = htonl(INADDR_NONE);
#else
		inet_pton(AF_INET, iaddr, &pcr.rule.src.addr.v.a.addr.v4.s_addr);
		pcr.rule.src.addr.v.a.mask.v4.s_addr = htonl(INADDR_NONE);
#endif
#ifdef __APPLE__
		pcr.rule.src.xport.range.op = PF_OP_EQ;
		pcr.rule.src.xport.range.port[0] = htons(iport);
		pcr.rule.src.xport.range.port[1] = htons(iport);
#else
		pcr.rule.src.port_op = PF_OP_EQ;
		pcr.rule.src.port[0] = htons(iport);
		pcr.rule.src.port[1] = htons(iport);
#endif
		if(rhost && rhost[0] != '\0' && rhost[0] != '*')
		{
#ifdef PFVAR_NEW_STYLE
			inet_pton(AF_INET, rhost, &pcr.rule.dst.addr.v.a.addr.v4addr.s_addr);
			pcr.rule.dst.addr.v.a.mask.v4addr.s_addr = htonl(INADDR_NONE);
#else
			inet_pton(AF_INET, rhost, &pcr.rule.dst.addr.v.a.addr.v4.s_addr);
			pcr.rule.dst.addr.v.a.mask.v4.s_addr = htonl(INADDR_NONE);
#endif
		}
#ifdef __APPLE__
		if(rport) {
			pcr.rule.dst.xport.range.op = PF_OP_EQ;
			pcr.rule.dst.xport.range.port[0] = htons(rport);
			pcr.rule.dst.xport.range.port[1] = htons(rport);
		} else {
			pcr.rule.dst.xport.range.op = PF_OP_NONE;
		}
#else
		if(rport) {
			pcr.rule.dst.port_op = PF_OP_EQ;
			pcr.rule.dst.port[0] = htons(rport);
			pcr.rule.dst.port[1] = htons(rport);
		} else {
			pcr.rule.dst.port_op = PF_OP_NONE;
		}
#endif
		/* -> xxx.xxx.xxx.xxx port 1234 */
#ifndef PF_NEWSTYLE
		pcr.rule.rpool.proxy_port[0] = eport;
		pcr.rule.rpool.proxy_port[1] = eport;
		TAILQ_INIT(&pcr.rule.rpool.list);
		a = calloc(1, sizeof(struct pf_pooladdr));
#ifdef PFVAR_NEW_STYLE
		inet_pton(AF_INET, extaddr, &a->addr.v.a.addr.v4addr.s_addr);
		a->addr.v.a.mask.v4addr.s_addr = htonl(INADDR_NONE);
#else
		inet_pton(AF_INET, extaddr, &a->addr.v.a.addr.v4.s_addr);
		a->addr.v.a.mask.v4.s_addr = htonl(INADDR_NONE);
#endif
		TAILQ_INSERT_TAIL(&pcr.rule.rpool.list, a, entries);

		memcpy(&pp.addr, a, sizeof(struct pf_pooladdr));
		pp.af = pcr.rule.af;
		if(ioctl(dev, DIOCADDADDR, &pp) < 0)
		{
			syslog(LOG_ERR, "ioctl(dev, DIOCADDADDR, ...): %m");
			r = -1;
		}
		else
		{
#else
		pcr.rule.nat.proxy_port[0] = eport;
		pcr.rule.nat.proxy_port[1] = eport;
		inet_pton(AF_INET, extaddr, &pcr.rule.nat.addr.v.a.addr.v4.s_addr);
		pcr.rule.nat.addr.v.a.mask.v4.s_addr = htonl(INADDR_NONE);
		{
#endif /* PF_NEWSTYLE */
			pcr.action = PF_CHANGE_GET_TICKET;
			if(ioctl(dev, DIOCCHANGERULE, &pcr) < 0)
			{
				syslog(LOG_ERR, "ioctl(dev, DIOCCHANGERULE, ...) PF_CHANGE_GET_TICKET: %m");
				r = -1;
			}
			else
			{
				pcr.action = PF_CHANGE_ADD_TAIL;
				if(ioctl(dev, DIOCCHANGERULE, &pcr) < 0)
				{
					syslog(LOG_ERR, "ioctl(dev, DIOCCHANGERULE, ...) PF_CHANGE_ADD_TAIL: %m");
					r = -1;
				}
			}
		}
#ifndef PF_NEWSTYLE
		free(a);
#endif
	}
	return r;
}

#ifdef ENABLE_PORT_TRIGGERING
int add_nat_rule(const char * ifname,
                 const char * rhost, unsigned short eport,
                 const char * iaddr, unsigned short iport, int proto,
                 const char * desc)
{
	return add_nat_rule_full(ifname, rhost, 0, NULL, eport,
	                         iaddr, iport, proto, desc);
}
#endif /* ENABLE_PORT_TRIGGERING */

/* action of the rules created by add_nat_rule(), used to select the
 * ruleset to scan when looking for a rule to delete.
 * The kernel maps the rule action to a ruleset number, so PF_NAT selects
 * PF_RULESET_NAT while PF_PASS selects PF_RULESET_FILTER. */
#ifndef PF_NEWSTYLE
#define NAT_RULE_ACTION	PF_NAT
#else
#define NAT_RULE_ACTION	PF_PASS	/* or PF_MATCH as we dont expect outbound packets to be blocked */
#endif

/* external port of a NAT rule, as set by add_nat_rule() */
#ifndef PF_NEWSTYLE
#define NAT_RULE_EPORT(r) ((r).rpool.proxy_port[0])
#else
#define NAT_RULE_EPORT(r) ((r).nat.proxy_port[0])
#endif

#ifdef ENABLE_PORT_TRIGGERING
/*
 * returns:  0 : OK
 *          -1 : ERROR
 *          -2 : Rule not found
 */
static int
delete_nat_rule(const char * ifname, unsigned short eport, unsigned short iport,
                int proto, in_addr_t iaddr)
{
	int i, n, r;
	unsigned int tnum;
#ifdef USE_LIBPFCTL
	struct pfctl_rules_info ri;
	struct pfctl_rule rule;
#define RULE (rule)
	char anchor_call[MAXPATHLEN] = "";
#else
	struct pfioc_rule pr;
#define RULE (pr.rule)
#endif
	UNUSED(ifname);
	if(dev<0) {
		syslog(LOG_ERR, "pf device is not open");
		return -1;
	}
#ifdef USE_LIBPFCTL
	if(pfctl_get_rules_info(dev, &ri, NAT_RULE_ACTION, anchor_name) < 0)
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
	RULE.action = PF_NAT;
#else
	RULE.action = PF_PASS;	/* or PF_MATCH as we dont expect outbound packets to be blocked */
	RULE.direction = PF_OUT;
#endif
	if(ioctl(dev, DIOCGETRULES, &pr) < 0)
	{
		syslog(LOG_ERR, "ioctl(dev, DIOCGETRULES, ...): %m");
		return -1;
	}
	n = pr.nr;
#ifdef PF_RELEASETICKETS
	tnum = pr.ticket;
#endif /* PF_RELEASETICKETS */
#endif /* USE_LIBPFCTL */
	r = -2;	/* not found */
	for(i=0; i<n; i++)
	{
#ifdef USE_LIBPFCTL
		if(pfctl_get_rule(dev, i, ri.ticket, anchor_name, NAT_RULE_ACTION, &rule, anchor_call) < 0)
		{
			syslog(LOG_ERR, "pfctl_get_rule(): %m");
			r = -1;
			break;
		}
#else /* USE_LIBPFCTL */
		pr.nr = i;
		if(ioctl(dev, DIOCGETRULE, &pr) < 0)
		{
			syslog(LOG_ERR, "ioctl(dev, DIOCGETRULE): %m");
			r = -1;
			break;
		}
#endif /* USE_LIBPFCTL */
#ifdef TEST
		syslog(LOG_DEBUG, "%2d port=%hu proto=%d addr=%8x    %8x",
		       i, ntohs(RULE.src.port[0]), RULE.proto,
		       RULE.src.addr.v.a.addr.v4.s_addr, iaddr);
#endif /* TEST */
		/* a client can have several mappings from the same iaddr:iport :
		 * the external port (set by add_nat_rule()) tells them apart */
#ifdef __APPLE__
		if(iport == ntohs(RULE.src.xport.range.port[0])
		 && RULE.proto == proto
		 && iaddr == RULE.src.addr.v.a.addr.v4.s_addr
		 && eport == NAT_RULE_EPORT(RULE))
#else
		if(iport == ntohs(RULE.src.port[0])
		 && RULE.proto == proto
		 && iaddr == RULE.src.addr.v.a.addr.v4.s_addr
		 && eport == NAT_RULE_EPORT(RULE))
#endif
		{
#ifdef USE_LIBPFCTL
			/* to change with the libpfctl alternative to DIOCCHANGERULE */
			struct pfioc_rule pr;
			memset(&pr, 0, sizeof(pr));
			strlcpy(pr.anchor, anchor_name, MAXPATHLEN);
			pr.ticket = ri.ticket;
			pr.rule.action = NAT_RULE_ACTION;	/* selects the ruleset for the DIOCCHANGERULE calls */
#endif
			pr.action = PF_CHANGE_GET_TICKET;
			if(ioctl(dev, DIOCCHANGERULE, &pr) < 0)
			{
				syslog(LOG_ERR, "ioctl(dev, DIOCCHANGERULE, ...) PF_CHANGE_GET_TICKET: %m");
				r = -1;
				break;
			}
			pr.action = PF_CHANGE_REMOVE;
			pr.nr = i;
			if(ioctl(dev, DIOCCHANGERULE, &pr) < 0)
			{
				syslog(LOG_ERR, "ioctl(dev, DIOCCHANGERULE, ...) PF_CHANGE_REMOVE: %m");
				r = -1;
			}
			else
			{
				r = 0;
			}
			break;
		}
	}
	if (r == -2)
		syslog(LOG_NOTICE, "could not find nat rule to delete eport=%hu iport=%hu addr=%8x", eport, iport, ntohl(iaddr));
	release_ticket(dev, tnum);
	return r;
}
#endif /* ENABLE_PORT_TRIGGERING */

#ifdef PCP_PEER
/* PCP PEER (IPv4 only, see RFC 6887 section 12) is a source NAT rule
 *   nat on ext_if inet proto udp from iaddr port iport to rhost port rport \
 *       -> eaddr port eport
 * stored in the anchor.  Replies are handled by the state it creates.
 * Rules are told apart from port triggering rules by their remote port. */
#ifdef __APPLE__
#define RULE_SPORT(r)	((r).src.xport.range.port[0])
#define RULE_DPORT(r)	((r).dst.xport.range.port[0])
#define RULE_DPORT_OP(r)	((r).dst.xport.range.op)
#else
#define RULE_SPORT(r)	((r).src.port[0])
#define RULE_DPORT(r)	((r).dst.port[0])
#define RULE_DPORT_OP(r)	((r).dst.port_op)
#endif
#ifdef PFVAR_NEW_STYLE
#define RULE_V4(x)	((x).v.a.addr.v4addr.s_addr)
#else
#define RULE_V4(x)	((x).v.a.addr.v4.s_addr)
#endif

/* PEER leases use the full endpoint key */
struct peer_lease {
	struct peer_lease *next;
	in_addr_t iaddr, raddr;
	unsigned short iport, rport;
	int proto;
	unsigned int timestamp;
};
static struct peer_lease *peer_leases = NULL;

static struct peer_lease **
find_peer_lease(in_addr_t iaddr, unsigned short iport,
                in_addr_t raddr, unsigned short rport, int proto)
{
	struct peer_lease **p = &peer_leases;
	while (*p != NULL) {
		if ((*p)->iaddr == iaddr && (*p)->iport == iport &&
		    (*p)->raddr == raddr && (*p)->rport == rport && (*p)->proto == proto)
			break;
		p = &(*p)->next;
	}
	return p;
}

static void
free_peer_leases(void)
{
	while (peer_leases != NULL) {
		struct peer_lease *old = peer_leases;
		peer_leases = old->next;
		free(old);
	}
}

struct peer_nat {
	in_addr_t iaddr, raddr;	/* network byte order */
	unsigned short iport, rport, eport;	/* host byte order */
	int proto;
	char desc[PF_RULE_LABEL_SIZE];
	char ifname[IFNAMSIZ];
	u_int64_t packets, bytes;
};

#define PEER_GET	0
#define PEER_DELETE	1
/* PEER_GET : fill *pn with the index-th PEER rule
 * PEER_DELETE : delete the rule matching iaddr/iport/raddr/rport/proto of *pn
 * returns:  0 : OK
 *          -1 : Error
 *          -2 : rule not found */
static int
peer_nat_walk(int op, int index, struct peer_nat * pn)
{
	int i, n, r, count;
	unsigned int tnum = 0;
#ifdef USE_LIBPFCTL
	struct pfctl_rules_info ri;
	struct pfctl_rule rule;
#define RULE (rule)
	char anchor_call[MAXPATHLEN] = "";
#else
	struct pfioc_rule pr;
#define RULE (pr.rule)
#endif
	if(dev<0) {
		syslog(LOG_ERR, "pf device is not open");
		return -1;
	}
#ifdef USE_LIBPFCTL
	if(pfctl_get_rules_info(dev, &ri, NAT_RULE_ACTION, anchor_name) < 0)
	{
		syslog(LOG_ERR, "pfctl_get_rules_info: %m");
		return -1;
	}
	n = ri.nr;
#ifdef PF_RELEASETICKETS
	tnum = ri.ticket;
#endif
#else
	memset(&pr, 0, sizeof(pr));
	strlcpy(pr.anchor, anchor_name, MAXPATHLEN);
#ifndef PF_NEWSTYLE
	RULE.action = PF_NAT;
#else
	RULE.action = PF_PASS;
	RULE.direction = PF_OUT;
#endif
	if(ioctl(dev, DIOCGETRULES, &pr) < 0)
	{
		syslog(LOG_ERR, "ioctl(dev, DIOCGETRULES, ...): %m");
		return -1;
	}
	n = pr.nr;
#ifdef PF_RELEASETICKETS
	tnum = pr.ticket;
#endif
#endif /* USE_LIBPFCTL */
	r = -2;
	count = 0;
	for(i=0; i<n; i++)
	{
#ifdef USE_LIBPFCTL
		if(pfctl_get_rule(dev, i, ri.ticket, anchor_name, NAT_RULE_ACTION, &rule, anchor_call) < 0)
		{
			syslog(LOG_ERR, "pfctl_get_rule(): %m");
			r = -1;
			break;
		}
#else
		pr.nr = i;
		if(ioctl(dev, DIOCGETRULE, &pr) < 0)
		{
			syslog(LOG_ERR, "ioctl(dev, DIOCGETRULE): %m");
			r = -1;
			break;
		}
#endif
		if(RULE_DPORT_OP(RULE) != PF_OP_EQ || RULE.af != AF_INET)
			continue;	/* not a PEER rule */
		if(op == PEER_GET)
		{
			if(count++ != index)
				continue;
			pn->iaddr = RULE_V4(RULE.src.addr);
			pn->raddr = RULE_V4(RULE.dst.addr);
			pn->iport = ntohs(RULE_SPORT(RULE));
			pn->rport = ntohs(RULE_DPORT(RULE));
			pn->eport = NAT_RULE_EPORT(RULE);
			pn->proto = RULE.proto;
#ifdef USE_LIBPFCTL
			strlcpy(pn->desc, RULE.label[0], sizeof(pn->desc));
#else
			strlcpy(pn->desc, RULE.label, sizeof(pn->desc));
#endif
			strlcpy(pn->ifname, RULE.ifname, sizeof(pn->ifname));
#ifdef PFRULE_INOUT_COUNTS
			pn->packets = RULE.packets[0] + RULE.packets[1];
			pn->bytes = RULE.bytes[0] + RULE.bytes[1];
#else
			pn->packets = RULE.packets;
			pn->bytes = RULE.bytes;
#endif
			r = 0;
			break;
		}
		if(pn->iport == ntohs(RULE_SPORT(RULE))
		 && pn->rport == ntohs(RULE_DPORT(RULE))
		 && RULE.proto == pn->proto
		 && pn->iaddr == RULE_V4(RULE.src.addr)
		 && pn->raddr == RULE_V4(RULE.dst.addr))
		{
#ifdef USE_LIBPFCTL
			struct pfioc_rule pr;
			memset(&pr, 0, sizeof(pr));
			strlcpy(pr.anchor, anchor_name, MAXPATHLEN);
			pr.ticket = ri.ticket;
			pr.rule.action = NAT_RULE_ACTION;
#endif
			pr.action = PF_CHANGE_GET_TICKET;
			if(ioctl(dev, DIOCCHANGERULE, &pr) < 0)
			{
				syslog(LOG_ERR, "ioctl(dev, DIOCCHANGERULE, ...) PF_CHANGE_GET_TICKET: %m");
				r = -1;
				break;
			}
			pr.action = PF_CHANGE_REMOVE;
			pr.nr = i;
			if(ioctl(dev, DIOCCHANGERULE, &pr) < 0)
			{
				syslog(LOG_ERR, "ioctl(dev, DIOCCHANGERULE, ...) PF_CHANGE_REMOVE: %m");
				r = -1;
			}
			else
				r = 0;
			break;
		}
	}
	release_ticket(dev, tnum);
	return r;
#undef RULE
}

/* find the PEER rule with this key; returns 0 if found */
static int
find_peer_nat(in_addr_t iaddr, unsigned short iport,
              in_addr_t raddr, unsigned short rport, int proto,
              struct peer_nat * pn)
{
	int i;
	for(i = 0; peer_nat_walk(PEER_GET, i, pn) == 0; i++)
	{
		if(pn->iaddr == iaddr && pn->iport == iport &&
		   pn->raddr == raddr && pn->rport == rport && pn->proto == proto)
			return 0;
	}
	return -1;
}

int
delete_peer_rule(const char * iaddr, unsigned short iport,
                 const char * raddr, unsigned short rport, int proto)
{
	struct peer_nat pn;
	struct peer_lease **leasep;
	int r;
	memset(&pn, 0, sizeof(pn));
	if(inet_pton(AF_INET, iaddr, &pn.iaddr) != 1 ||
	   inet_pton(AF_INET, raddr, &pn.raddr) != 1)
		return -1;
	pn.iport = iport;
	pn.rport = rport;
	pn.proto = proto;
	r = peer_nat_walk(PEER_DELETE, 0, &pn);
	if(r == -1)
		return -1;
	/* also discard stale lease state if the rule was removed outside */
	leasep = find_peer_lease(pn.iaddr, iport, pn.raddr, rport, proto);
	if(*leasep != NULL) {
		struct peer_lease *old = *leasep;
		*leasep = old->next;
		free(old);
	}
	return 0;
}

unsigned int
expire_peer_rules(unsigned int now)
{
	struct peer_lease *lease = peer_leases;
	unsigned int next = 0;
	while(lease != NULL) {
		struct peer_lease *following = lease->next;
		if(lease->timestamp != 0 && lease->timestamp <= now) {
			char iaddr[INET_ADDRSTRLEN], raddr[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &lease->iaddr, iaddr, sizeof(iaddr));
			inet_ntop(AF_INET, &lease->raddr, raddr, sizeof(raddr));
			syslog(LOG_NOTICE, "remove PEER mapping %s:%hu -> %s:%hu because it has expired",
			       iaddr, lease->iport, raddr, lease->rport);
			if(delete_peer_rule(iaddr, lease->iport, raddr, lease->rport, lease->proto) < 0)
				next = now + 1;
		} else if(lease->timestamp != 0 && (next == 0 || lease->timestamp < next)) {
			next = lease->timestamp;
		}
		lease = following;
	}
	return next;
}

int
add_peer_redirect_rule2(const char * ifname,
                        const char * rhost, unsigned short rport,
                        const char * eaddr, unsigned short eport,
                        const char * iaddr, unsigned short iport, int proto,
                        const char * desc, unsigned int timestamp)
{
	struct peer_nat pn;
	struct peer_lease **leasep, *lease;
	in_addr_t ia, ra;
	int new_lease, r;

	if(inet_pton(AF_INET, iaddr, &ia) != 1 || inet_pton(AF_INET, rhost, &ra) != 1)
		return -1;
	leasep = find_peer_lease(ia, iport, ra, rport, proto);
	lease = *leasep;
	new_lease = (lease == NULL);
	if(new_lease) {
		lease = calloc(1, sizeof(*lease));
		if(lease == NULL)
			return -1;
		lease->iaddr = ia;
		lease->iport = iport;
		lease->raddr = ra;
		lease->rport = rport;
		lease->proto = proto;
	}
	if(find_peer_nat(ia, iport, ra, rport, proto, &pn) == 0) {
		if(pn.eport == eport && strcmp(pn.desc, desc) == 0) {
			/* renewal : keep the rule, and its states */
			r = 0;
			goto done;
		}
		/* different external port or description : replace the rule.
		 * delete_peer_rule() also frees the lease we found above. */
		if(delete_peer_rule(iaddr, iport, rhost, rport, proto) < 0) {
			r = -1;
			goto done;
		}
		if(!new_lease) {
			lease = calloc(1, sizeof(*lease));
			if(lease == NULL)
				return -1;
			lease->iaddr = ia;
			lease->iport = iport;
			lease->raddr = ra;
			lease->rport = rport;
			lease->proto = proto;
			new_lease = 1;
		}
	}
	r = add_nat_rule_full(ifname, rhost, rport, eaddr, eport,
	                      iaddr, iport, proto, desc);
done:
	if(r >= 0) {
		lease->timestamp = timestamp;
		if(new_lease) {
			lease->next = peer_leases;
			peer_leases = lease;
		}
	} else if(new_lease) {
		free(lease);
	}
	return r;
}

/* DSCP marking is not supported with pf */
int
add_peer_dscp_rule2(const char * ifname,
                    const char * rhost, unsigned short rport,
                    unsigned char dscp,
                    const char * iaddr, unsigned short iport, int proto,
                    const char * desc, unsigned int timestamp)
{
	UNUSED(ifname); UNUSED(rhost); UNUSED(rport); UNUSED(dscp);
	UNUSED(iaddr); UNUSED(iport); UNUSED(proto); UNUSED(desc);
	UNUSED(timestamp);
	syslog(LOG_ERR, "add_peer_dscp_rule2: not supported");
	return -1;
}

int
get_peer_rule_by_index(int index,
                       char * ifname, unsigned short * eport,
                       char * iaddr, int iaddrlen, unsigned short * iport,
                       int * proto, char * desc, int desclen,
                       char * rhost, int rhostlen, unsigned short * rport,
                       unsigned int * timestamp,
                       u_int64_t * packets, u_int64_t * bytes)
{
	struct peer_nat pn;
	if(index < 0 || peer_nat_walk(PEER_GET, index, &pn) != 0)
		return -1;
	if(ifname)
		strlcpy(ifname, pn.ifname, IFNAMSIZ);
	if(eport)
		*eport = pn.eport;
	if(iaddr && iaddrlen > 0)
		inet_ntop(AF_INET, &pn.iaddr, iaddr, iaddrlen);
	if(iport)
		*iport = pn.iport;
	if(proto)
		*proto = pn.proto;
	if(desc && desclen > 0)
		strlcpy(desc, pn.desc, desclen);
	if(rhost && rhostlen > 0)
		inet_ntop(AF_INET, &pn.raddr, rhost, rhostlen);
	if(rport)
		*rport = pn.rport;
	if(timestamp) {
		struct peer_lease * lease = *find_peer_lease(pn.iaddr, pn.iport,
		                                             pn.raddr, pn.rport, pn.proto);
		*timestamp = lease ? lease->timestamp : 0;
	}
	if(packets)
		*packets = pn.packets;
	if(bytes)
		*bytes = pn.bytes;
	return 0;
}

/* get_nat_ext_addr()
 * Look in the pf state table for an existing translated flow
 * src -> dst and return its external source address and port.
 * returns 1 if found, 0 if not, -1 on error. IPv4 only. */
#define PFA4(a)	((a).v4.s_addr)
#ifdef PF_SK_STACK
#define PFSK_STACK	PF_SK_STACK
#define PFSK_WIRE	PF_SK_WIRE
#else
#define PFSK_WIRE	0
#define PFSK_STACK	1
#endif
static int
nat_state_ext(const struct pf_addr * ia, const uint16_t * ip,
              const struct pf_addr * wa, const uint16_t * wp,
              in_addr_t src, uint16_t sport, in_addr_t dst, uint16_t dport,
              struct sockaddr_in * ext)
{
	int a;
	for(a = 0; a < 2; a++)
	{
		if(PFA4(ia[a]) == src && ip[a] == htons(sport) &&
		   PFA4(ia[1-a]) == dst && ip[1-a] == htons(dport) &&
		   PFA4(wa[1-a]) == dst && wp[1-a] == htons(dport) &&
		   (PFA4(wa[a]) != src || wp[a] != htons(sport)))
		{
			memset(ext, 0, sizeof(*ext));
			ext->sin_family = AF_INET;
			ext->sin_addr.s_addr = PFA4(wa[a]);
			ext->sin_port = wp[a];
			return 1;
		}
	}
	return 0;
}

int
get_nat_ext_addr(struct sockaddr * src, struct sockaddr * dst, uint8_t proto,
                 struct sockaddr_storage * ret_ext)
{
	struct sockaddr_in * s4 = (struct sockaddr_in *)src;
	struct sockaddr_in * d4 = (struct sockaddr_in *)dst;
	struct sockaddr_in ext;
	int found = 0;
	if(dev < 0 || !src || !dst || src->sa_family != AF_INET ||
	   dst->sa_family != AF_INET)
		return 0;
#ifdef USE_LIBPFCTL
	{
		struct pfctl_states states;
		struct pfctl_state * st;
		memset(&states, 0, sizeof(states));
		TAILQ_INIT(&states.states);
		if(pfctl_get_states(dev, &states) != 0)
		{
			syslog(LOG_ERR, "pfctl_get_states: %m");
			return -1;
		}
		TAILQ_FOREACH(st, &states.states, entry)
		{
			uint16_t ip[2], wp[2];
			struct pf_addr ia[2], wa[2];
			int k;
			if(st->key[PFSK_STACK].proto != proto)
				continue;
			for(k = 0; k < 2; k++)
			{
				ia[k] = st->key[PFSK_STACK].addr[k];
				ip[k] = st->key[PFSK_STACK].port[k];
				wa[k] = st->key[PFSK_WIRE].addr[k];
				wp[k] = st->key[PFSK_WIRE].port[k];
			}
			found = nat_state_ext(ia, ip, wa, wp,
			                      s4->sin_addr.s_addr, ntohs(s4->sin_port),
			                      d4->sin_addr.s_addr, ntohs(d4->sin_port), &ext);
			if(found)
				break;
		}
		pfctl_free_states(&states);
	}
#else
	{
		struct pfioc_states ps;
		struct pfsync_state * st;
		char * buf = NULL;
		size_t len = 0;
		int i, n;
		memset(&ps, 0, sizeof(ps));
		/* the size of the table may change between the 2 calls */
		for(;;)
		{
			if(ioctl(dev, DIOCGETSTATES, &ps) < 0)
			{
				syslog(LOG_ERR, "ioctl(dev, DIOCGETSTATES, ...): %m");
				free(buf);
				return -1;
			}
			if(ps.ps_len <= (int)len && buf != NULL)
				break;
			len = ps.ps_len + 16 * sizeof(struct pfsync_state);
			free(buf);
			buf = malloc(len);
			if(buf == NULL)
				return -1;
			ps.ps_len = len;
			ps.ps_buf = buf;
		}
		n = ps.ps_len / sizeof(struct pfsync_state);
		st = (struct pfsync_state *)ps.ps_buf;
		for(i = 0; i < n && !found; i++, st++)
		{
			uint16_t ip[2], wp[2];
			struct pf_addr ia[2], wa[2];
			int k;
			if(st->proto != proto)
				continue;
			for(k = 0; k < 2; k++)
			{
				ia[k] = st->key[PF_SK_STACK].addr[k];
				ip[k] = st->key[PF_SK_STACK].port[k];
				wa[k] = st->key[PF_SK_WIRE].addr[k];
				wp[k] = st->key[PF_SK_WIRE].port[k];
			}
			found = nat_state_ext(ia, ip, wa, wp,
			                      s4->sin_addr.s_addr, ntohs(s4->sin_port),
			                      d4->sin_addr.s_addr, ntohs(d4->sin_port), &ext);
		}
		free(buf);
	}
#endif
	if(found)
		memcpy(ret_ext, &ext, sizeof(ext));
	return found;
}
#endif /* PCP_PEER */
#endif

/* IPv4 netmask for a prefix length (network byte order) */
static in_addr_t
prefix_to_mask4(unsigned int prefix)
{
	return prefix == 0 ? 0 : htonl(0xffffffffU << (32 - prefix));
}

#ifdef __APPLE__
#define SRC_PORT_SET(rule, p) do { \
		(rule).src.xport.range.op = PF_OP_EQ; \
		(rule).src.xport.range.port[0] = htons(p); \
		(rule).src.xport.range.port[1] = htons(p); } while(0)
#else
#define SRC_PORT_SET(rule, p) do { \
		(rule).src.port_op = PF_OP_EQ; \
		(rule).src.port[0] = htons(p); \
		(rule).src.port[1] = htons(p); } while(0)
#endif

/* add_redirect_rule_ex() :
 * create a rdr rule. The source is restricted to saddr/prefix (network
 * byte order address, prefix 0 means any) and to sport if not 0. */
static int
add_redirect_rule_ex(const char * ifname,
                     in_addr_t saddr, unsigned int prefix, unsigned short sport,
                     unsigned short eport,
                     const char * iaddr, unsigned short iport, int proto,
                     const char * desc)
{
	int r;
	struct pfioc_rule pcr;
#ifndef PF_NEWSTYLE
	struct pfioc_pooladdr pp;
	struct pf_pooladdr *a;
#endif

	if(dev<0) {
		syslog(LOG_ERR, "pf device is not open");
		return -1;
	}
	r = 0;
	memset(&pcr, 0, sizeof(pcr));
	strlcpy(pcr.anchor, anchor_name, MAXPATHLEN);

#ifndef PF_NEWSTYLE
	memset(&pp, 0, sizeof(pp));
	strlcpy(pp.anchor, anchor_name, MAXPATHLEN);
	if(ioctl(dev, DIOCBEGINADDRS, &pp) < 0)
	{
		syslog(LOG_ERR, "ioctl(dev, DIOCBEGINADDRS, ...): %m");
		r = -1;
	}
	else
	{
		pcr.pool_ticket = pp.ticket;
#else
	if(1)
	{
		pcr.rule.direction = PF_IN;
		pcr.rule.nat.addr.type = PF_ADDR_NONE;
		pcr.rule.rdr.addr.type = PF_ADDR_ADDRMASK;
#endif
		/*pcr.rule.src.addr.type = PF_ADDR_NONE;*/
		pcr.rule.src.addr.type = PF_ADDR_ADDRMASK;
		pcr.rule.dst.addr.type = PF_ADDR_ADDRMASK;

#ifdef __APPLE__
		pcr.rule.dst.xport.range.op = PF_OP_EQ;
		pcr.rule.dst.xport.range.port[0] = htons(eport);
		pcr.rule.dst.xport.range.port[1] = htons(eport);
#else
		pcr.rule.dst.port_op = PF_OP_EQ;
		pcr.rule.dst.port[0] = htons(eport);
		pcr.rule.dst.port[1] = htons(eport);
#endif
#ifndef PF_NEWSTYLE
		pcr.rule.action = PF_RDR;
#ifndef PF_ENABLE_FILTER_RULES
		pcr.rule.natpass = 1;
#else
		pcr.rule.natpass = 0;
#endif
#else
#ifndef PF_ENABLE_FILTER_RULES
		pcr.rule.action = PF_PASS;
#else
		pcr.rule.action = PF_MATCH;
#endif
#endif
		pcr.rule.af = AF_INET;
#ifdef USE_IFNAME_IN_RULES
		if(ifname)
			strlcpy(pcr.rule.ifname, ifname, IFNAMSIZ);
#endif
		pcr.rule.proto = proto;
		pcr.rule.log = (GETFLAG(LOGPACKETSMASK))?1:0;	/*logpackets;*/
#ifdef PFRULE_HAS_RTABLEID
		pcr.rule.rtableid = -1;	/* first appeared in OpenBSD 4.0 */
#endif
#ifdef PFRULE_HAS_ONRDOMAIN
		pcr.rule.onrdomain = -1;	/* first appeared in OpenBSD 5.0 */
#endif
		pcr.rule.quick = 1;
		pcr.rule.keep_state = PF_STATE_NORMAL;
		if(tag)
			strlcpy(pcr.rule.tagname, tag, PF_TAG_NAME_SIZE);
		strlcpy(pcr.rule.label, desc, PF_RULE_LABEL_SIZE);
		if(prefix > 0)
		{
#ifdef PFVAR_NEW_STYLE
			pcr.rule.src.addr.v.a.addr.v4addr.s_addr = saddr & prefix_to_mask4(prefix);
			pcr.rule.src.addr.v.a.mask.v4addr.s_addr = prefix_to_mask4(prefix);
#else
			pcr.rule.src.addr.v.a.addr.v4.s_addr = saddr & prefix_to_mask4(prefix);
			pcr.rule.src.addr.v.a.mask.v4.s_addr = prefix_to_mask4(prefix);
#endif
		}
		if(sport)
			SRC_PORT_SET(pcr.rule, sport);
#ifdef PF_SET_DST_ADDR
		/* set dst address
		 * see https://github.com/miniupnp/miniupnp/issues/231 */
		if(use_ext_ip_addr && use_ext_ip_addr[0] != '\0')
		{
#ifdef PFVAR_NEW_STYLE
			inet_pton(AF_INET, use_ext_ip_addr, &pcr.rule.dst.addr.v.a.addr.v4addr.s_addr);
			pcr.rule.dst.addr.v.a.mask.v4addr.s_addr = htonl(INADDR_NONE);
#else
			inet_pton(AF_INET, use_ext_ip_addr, &pcr.rule.dst.addr.v.a.addr.v4.s_addr);
			pcr.rule.dst.addr.v.a.mask.v4.s_addr = htonl(INADDR_NONE);
#endif
		}
#endif /* PF_SET_DST_ADDR */
#ifndef PF_NEWSTYLE
		pcr.rule.rpool.proxy_port[0] = iport;
		pcr.rule.rpool.proxy_port[1] = iport;
		TAILQ_INIT(&pcr.rule.rpool.list);
		a = calloc(1, sizeof(struct pf_pooladdr));
#ifdef PFVAR_NEW_STYLE
		inet_pton(AF_INET, iaddr, &a->addr.v.a.addr.v4addr.s_addr);
		a->addr.v.a.mask.v4addr.s_addr = htonl(INADDR_NONE);
#else
		inet_pton(AF_INET, iaddr, &a->addr.v.a.addr.v4.s_addr);
		a->addr.v.a.mask.v4.s_addr = htonl(INADDR_NONE);
#endif
		TAILQ_INSERT_TAIL(&pcr.rule.rpool.list, a, entries);

		memcpy(&pp.addr, a, sizeof(struct pf_pooladdr));
		pp.af = pcr.rule.af;
		if(ioctl(dev, DIOCADDADDR, &pp) < 0)
		{
			syslog(LOG_ERR, "ioctl(dev, DIOCADDADDR, ...): %m");
			r = -1;
		}
		else
		{
#else
		pcr.rule.rdr.proxy_port[0] = iport;
		pcr.rule.rdr.proxy_port[1] = iport;
		inet_pton(AF_INET, iaddr, &pcr.rule.rdr.addr.v.a.addr.v4.s_addr);
		pcr.rule.rdr.addr.v.a.mask.v4.s_addr = htonl(INADDR_NONE);
		if(1)
		{
#endif
			pcr.action = PF_CHANGE_GET_TICKET;
			if(ioctl(dev, DIOCCHANGERULE, &pcr) < 0)
			{
				syslog(LOG_ERR, "ioctl(dev, DIOCCHANGERULE, ...) PF_CHANGE_GET_TICKET: %m");
				r = -1;
			}
			else
			{
				pcr.action = PF_CHANGE_ADD_TAIL;
				if(ioctl(dev, DIOCCHANGERULE, &pcr) < 0)
				{
					syslog(LOG_ERR, "ioctl(dev, DIOCCHANGERULE, ...) PF_CHANGE_ADD_TAIL: %m");
					r = -1;
				}
			}
		}
#ifndef PF_NEWSTYLE
		free(a);
#endif
	}
	return r;
}

/* PCP MAP FILTER (RFC 6887 section 13.3) :
 * a filtered mapping is a group of rdr (and pass) rules, one per allowed
 * remote peer prefix/port, so traffic from other sources is never translated.
 * A policy for a mapping which is about to be created is kept pending until
 * add_redirect_rule2() and add_filter_rule2() have consumed it. */
struct pf_pcp_policy {
	struct in6_addr address;
	unsigned short port;
	unsigned char protocol;
	unsigned int count;
	struct pcp_filter filters[PCP_FILTER_PEER_MAX];
};

static struct pf_pcp_policy * pending_policy = NULL;

/* same for an IPv6 mapping (pinholes) */
unsigned int
pf_pcp_pending_filters6(const struct in6_addr * address, unsigned short port,
                        int protocol, const struct pcp_filter ** filters)
{
	if(pending_policy == NULL || pending_policy->count == 0 ||
	   pending_policy->port != port || pending_policy->protocol != protocol ||
	   memcmp(&pending_policy->address, address, sizeof(*address)) != 0)
		return 0;
	*filters = pending_policy->filters;
	return pending_policy->count;
}

/* returns the number of filters to use for the mapping to iaddr:iport
 * (0 if no policy is pending for it) */
static unsigned int
pending_filters(const char * iaddr, unsigned short iport, int proto,
                const struct pcp_filter ** filters)
{
	struct in_addr a;
	if(pending_policy == NULL || pending_policy->count == 0 ||
	   pending_policy->port != iport || pending_policy->protocol != proto ||
	   inet_pton(AF_INET, iaddr, &a) != 1 ||
	   memcmp(pending_policy->address.s6_addr + 12, &a, 4) != 0)
		return 0;
	*filters = pending_policy->filters;
	return pending_policy->count;
}

/* add_redirect_rule2() :
 * create a rdr rule (or a rdr rule per allowed peer when a PCP FILTER
 * policy is pending for this internal endpoint) */
int
add_redirect_rule2(const char * ifname,
                   const char * rhost, unsigned short eport,
                   const char * iaddr, unsigned short iport, int proto,
                   const char * desc, unsigned int timestamp)
{
	int r = 0;
	unsigned int k, count;
	struct in_addr ra;
	const struct pcp_filter * filters = NULL;
	count = pending_filters(iaddr, iport, proto, &filters);
	if(count == 0)
	{
		unsigned int prefix = 0;
		ra.s_addr = 0;
		if(rhost && rhost[0] != '\0' && rhost[0] != '*')
		{
			if(inet_pton(AF_INET, rhost, &ra) == 1)
				prefix = 32;
		}
		r = add_redirect_rule_ex(ifname, ra.s_addr, prefix, 0,
		                         eport, iaddr, iport, proto, desc);
	}
	else
	{
		for(k = 0; k < count && r == 0; k++)
		{
			memcpy(&ra.s_addr, filters[k].address.s6_addr + 12, 4);
			r = add_redirect_rule_ex(ifname, ra.s_addr, filters[k].prefix - 96,
			                         filters[k].port,
			                         eport, iaddr, iport, proto, desc);
		}
	}
	if(r == 0 && timestamp > 0)
		add_timestamp_entry(eport, proto, timestamp);
#ifdef ENABLE_PORT_TRIGGERING
	if(r == 0 && proto == IPPROTO_UDP)
	{
		add_nat_rule(ifname, rhost, eport, iaddr, iport, proto, desc);
		/* TODO check error */
	}
#endif
	return r;
}

/* thanks to Seth Mos for this function */
static int
add_filter_rule_ex(const char * ifname,
                   in_addr_t saddr, unsigned int prefix, unsigned short sport,
                   const char * iaddr,
                   unsigned short eport, unsigned short iport,
                   int proto, const char * desc)
{
#ifndef PF_ENABLE_FILTER_RULES
	UNUSED(ifname);
	UNUSED(saddr); UNUSED(prefix); UNUSED(sport); UNUSED(iaddr);
	UNUSED(eport); UNUSED(iport);
	UNUSED(proto); UNUSED(desc);
	return 0;
#else
	int r;
	struct pfioc_rule pcr;
#ifndef PF_NEWSTYLE
	struct pfioc_pooladdr pp;
#endif
#ifndef USE_IFNAME_IN_RULES
	UNUSED(ifname);
#endif
	UNUSED(eport);
	if(dev<0) {
		syslog(LOG_ERR, "pf device is not open");
		return -1;
	}
	r = 0;
	memset(&pcr, 0, sizeof(pcr));
	strlcpy(pcr.anchor, anchor_name, MAXPATHLEN);

#ifndef PF_NEWSTYLE
	memset(&pp, 0, sizeof(pp));
	strlcpy(pp.anchor, anchor_name, MAXPATHLEN);
	if(ioctl(dev, DIOCBEGINADDRS, &pp) < 0)
	{
		syslog(LOG_ERR, "ioctl(dev, DIOCBEGINADDRS, ...): %m");
		r = -1;
	}
	else
	{
		pcr.pool_ticket = pp.ticket;
#else
	if(1)
	{
#endif
		pcr.rule.dst.port_op = PF_OP_EQ;
		pcr.rule.dst.port[0] = htons(iport);
		pcr.rule.direction = PF_IN;
		pcr.rule.action = PF_PASS;
		pcr.rule.af = AF_INET;
#ifdef USE_IFNAME_IN_RULES
		if(ifname)
			strlcpy(pcr.rule.ifname, ifname, IFNAMSIZ);
#endif
		pcr.rule.proto = proto;
		pcr.rule.quick = (GETFLAG(PFNOQUICKRULESMASK))?0:1;
		pcr.rule.log = (GETFLAG(LOGPACKETSMASK))?1:0;	/*logpackets;*/
/* see the discussion on the forum :
 * http://miniupnp.tuxfamily.org/forum/viewtopic.php?p=638 */
		pcr.rule.flags = TH_SYN;
		pcr.rule.flagset = (TH_SYN|TH_ACK);
#ifdef PFRULE_HAS_RTABLEID
		pcr.rule.rtableid = -1;	/* first appeared in OpenBSD 4.0 */
#endif
#ifdef PFRULE_HAS_ONRDOMAIN
		pcr.rule.onrdomain = -1;	/* first appeared in OpenBSD 5.0 */
#endif
		pcr.rule.keep_state = 1;
		strlcpy(pcr.rule.label, desc, PF_RULE_LABEL_SIZE);
		if(queue)
			strlcpy(pcr.rule.qname, queue, PF_QNAME_SIZE);
		if(tag)
			strlcpy(pcr.rule.tagname, tag, PF_TAG_NAME_SIZE);

		if(prefix > 0)
		{
			pcr.rule.src.addr.v.a.addr.v4.s_addr = saddr & prefix_to_mask4(prefix);
			pcr.rule.src.addr.v.a.mask.v4.s_addr = prefix_to_mask4(prefix);
		}
		if(sport)
			SRC_PORT_SET(pcr.rule, sport);
		/* we want any - iaddr port = # keep state label */
		inet_pton(AF_INET, iaddr, &pcr.rule.dst.addr.v.a.addr.v4.s_addr);
		pcr.rule.dst.addr.v.a.mask.v4.s_addr = htonl(INADDR_NONE);
#ifndef PF_NEWSTYLE
		pcr.rule.rpool.proxy_port[0] = iport;
		pcr.rule.rpool.proxy_port[1] = iport;
		TAILQ_INIT(&pcr.rule.rpool.list);
#endif
		if(1)
		{
			pcr.action = PF_CHANGE_GET_TICKET;
        	if(ioctl(dev, DIOCCHANGERULE, &pcr) < 0)
			{
            	syslog(LOG_ERR, "ioctl(dev, DIOCCHANGERULE, ...) PF_CHANGE_GET_TICKET: %m");
				r = -1;
			}
			else
			{
				pcr.action = PF_CHANGE_ADD_TAIL;
				if(ioctl(dev, DIOCCHANGERULE, &pcr) < 0)
				{
					syslog(LOG_ERR, "ioctl(dev, DIOCCHANGERULE, ...) PF_CHANGE_ADD_TAIL: %m");
					r = -1;
				}
			}
		}
	}
	return r;
#endif
}

int
add_filter_rule2(const char * ifname,
                 const char * rhost, const char * iaddr,
                 unsigned short eport, unsigned short iport,
                 int proto, const char * desc)
{
	int r = 0;
	unsigned int k, count;
	struct in_addr ra;
	const struct pcp_filter * filters = NULL;
	count = pending_filters(iaddr, iport, proto, &filters);
	if(count == 0)
	{
		unsigned int prefix = 0;
		ra.s_addr = 0;
		if(rhost && rhost[0] != '\0' && rhost[0] != '*')
		{
			if(inet_pton(AF_INET, rhost, &ra) == 1)
				prefix = 32;
		}
		return add_filter_rule_ex(ifname, ra.s_addr, prefix, 0, iaddr,
		                          eport, iport, proto, desc);
	}
	for(k = 0; k < count && r == 0; k++)
	{
		memcpy(&ra.s_addr, filters[k].address.s6_addr + 12, 4);
		r = add_filter_rule_ex(ifname, ra.s_addr, filters[k].prefix - 96,
		                       filters[k].port, iaddr,
		                       eport, iport, proto, desc);
	}
	return r;
}

/* get_redirect_rule_count()
 * return value : -1 for error or the number of rdr rules */
int
get_redirect_rule_count(const char * ifname)
{
#ifdef USE_LIBPFCTL
	struct pfctl_rules_info ri;
#else
	struct pfioc_rule pr;
#endif
	UNUSED(ifname);

	if(dev<0) {
		syslog(LOG_ERR, "pf device is not open");
		return -1;
	}
#ifdef USE_LIBPFCTL
	if (pfctl_get_rules_info(dev, &ri, PF_RDR, anchor_name) < 0)
	{
		syslog(LOG_ERR, "pfctl_get_rules_info: %m");
		return -1;
	}
	return ri.nr;
#else
	memset(&pr, 0, sizeof(pr));
	strlcpy(pr.anchor, anchor_name, MAXPATHLEN);
#ifndef PF_NEWSTYLE
	RULE.action = PF_RDR;
#endif
	if(ioctl(dev, DIOCGETRULES, &pr) < 0)
	{
		syslog(LOG_ERR, "ioctl(dev, DIOCGETRULES, ...): %m");
		return -1;
	}
	release_ticket(dev, pr.ticket);
	return pr.nr;
#endif
}

/* get_redirect_rule()
 * return value : 0 success (found)
 * -1 = error
 * -2 = rule not found */
int
get_redirect_rule(const char * ifname, unsigned short eport, int proto,
                  char * iaddr, int iaddrlen, unsigned short * iport,
                  char * desc, int desclen,
                  char * rhost, int rhostlen,
                  unsigned int * timestamp,
                  u_int64_t * packets, u_int64_t * bytes)
{
	int i, n, r;
	unsigned int tnum;
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
#ifndef PF_NEWSTYLE
	struct pfioc_pooladdr pp;
#endif
	UNUSED(ifname);

	if(dev<0) {
		syslog(LOG_ERR, "pf device is not open");
		return -1;
	}
#ifdef USE_LIBPFCTL
	if(pfctl_get_rules_info(dev, &ri, PF_RDR, anchor_name) < 0)
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
	RULE.action = PF_RDR;
#endif
	if(ioctl(dev, DIOCGETRULES, &pr) < 0)
	{
		syslog(LOG_ERR, "ioctl(dev, DIOCGETRULES, ...): %m");
		return -1;
	}
	n = pr.nr;
#ifdef PF_RELEASETICKETS
	tnum = pr.ticket;
#endif /* PF_RELEASETICKETS */
#endif /* USE_LIBPFCTL */
	r = -2;
	for(i=0; i<n; i++)
	{
#ifdef USE_LIBPFCTL
		if(pfctl_get_rule(dev, i, ri.ticket, anchor_name, PF_RDR, &rule, anchor_call) < 0)
		{
			syslog(LOG_ERR, "pfctl_get_rule: %m");
			r = -1;
			break;
		}
#else /* USE_LIBPFCTL */
		pr.nr = i;
		if(ioctl(dev, DIOCGETRULE, &pr) < 0)
		{
			syslog(LOG_ERR, "ioctl(dev, DIOCGETRULE): %m");
			r = -1;
			break;
		}
#endif /* USE_LIBPFCTL */
#ifdef __APPLE__
		if( (eport == ntohs(RULE.dst.xport.range.port[0]))
		  && (eport == ntohs(RULE.dst.xport.range.port[1]))
#else
		if( (eport == ntohs(RULE.dst.port[0]))
		  && (eport == ntohs(RULE.dst.port[1]))
#endif
		  && (RULE.proto == proto) )
		{
#ifndef PF_NEWSTYLE
			*iport = RULE.rpool.proxy_port[0];
#else
			*iport = RULE.rdr.proxy_port[0];
#endif
			if(desc)
#ifdef USE_LIBPFCTL
				strlcpy(desc, RULE.label[0], desclen);
#else /* USE_LIBPFCTL */
				strlcpy(desc, RULE.label, desclen);
#endif /* USE_LIBPFCTL */
#ifdef PFRULE_INOUT_COUNTS
			if(packets)
				*packets = RULE.packets[0] + RULE.packets[1];
			if(bytes)
				*bytes = RULE.bytes[0] + RULE.bytes[1];
#else
			if(packets)
				*packets = RULE.packets;
			if(bytes)
				*bytes = RULE.bytes;
#endif
#ifndef PF_NEWSTYLE
			memset(&pp, 0, sizeof(pp));
			strlcpy(pp.anchor, anchor_name, MAXPATHLEN);
			pp.r_action = PF_RDR;
			pp.r_num = i;
#ifdef USE_LIBPFCTL
			pp.ticket = ri.ticket;
#else /* USE_LIBPFCTL */
			pp.ticket = pr.ticket;
#endif /* USE_LIBPFCTL */
			if(ioctl(dev, DIOCGETADDRS, &pp) < 0)
			{
				syslog(LOG_ERR, "ioctl(dev, DIOCGETADDRS, ...): %m");
				r = -1;
				break;
			}
			if(pp.nr != 1)
			{
				syslog(LOG_NOTICE, "No address associated with pf rule");
				r = -1;
				break;
			}
			pp.nr = 0;	/* first */
			if(ioctl(dev, DIOCGETADDR, &pp) < 0)
			{
				syslog(LOG_ERR, "ioctl(dev, DIOCGETADDR, ...): %m");
				r = -1;
				break;
			}
#ifdef PFVAR_NEW_STYLE
			inet_ntop(AF_INET, &pp.addr.addr.v.a.addr.v4addr.s_addr,
			          iaddr, iaddrlen);
#else
			inet_ntop(AF_INET, &pp.addr.addr.v.a.addr.v4.s_addr,
			          iaddr, iaddrlen);
#endif
#else
			inet_ntop(AF_INET, &RULE.rdr.addr.v.a.addr.v4.s_addr,
			          iaddr, iaddrlen);
#endif
			if(rhost && rhostlen > 0)
			{
#ifdef PFVAR_NEW_STYLE
				if (RULE.src.addr.v.a.addr.v4addr.s_addr == 0)
#else
				if (RULE.src.addr.v.a.addr.v4.s_addr == 0)
#endif
				{
					rhost[0] = '\0'; /* empty string */
				}
				else
				{
#ifdef PFVAR_NEW_STYLE
					inet_ntop(AF_INET, &RULE.src.addr.v.a.addr.v4addr.s_addr,
					          rhost, rhostlen);
#else
					inet_ntop(AF_INET, &RULE.src.addr.v.a.addr.v4.s_addr,
					          rhost, rhostlen);
#endif
				}
			}
			if(timestamp)
				*timestamp = get_timestamp(eport, proto);
			r = 0;
			break;
		}
	}
	release_ticket(dev, tnum);
	return r;
}

#define priv_delete_redirect_rule(ifname, eport, proto, iport, \
                                  iaddr, rhost, rhostlen) \
        priv_delete_redirect_rule_check_desc(ifname, eport, proto, iport, \
                                             iaddr, rhost, rhostlen, 0, NULL)
/* if check_desc is true, only delete the rule if the description differs.
 * returns : -2 : rule not found
 *           -1 : error
 *            0 : rule deleted
 *            1 : rule untouched
 */
/* set to avoid logging when looking for more rules of a filtered mapping */
static int quiet_not_found = 0;

static int
priv_delete_redirect_rule_check_desc(const char * ifname, unsigned short eport,
                          int proto, unsigned short * iport,
                          in_addr_t * iaddr, char * rhost, int rhostlen,
                          int check_desc, const char * desc)
{
	int i, n, r;
	unsigned int tnum;
	struct pfioc_rule pr;
#ifdef USE_LIBPFCTL
	struct pfctl_rules_info ri;
	struct pfctl_rule rule;
#define RULE (rule)
	char anchor_call[MAXPATHLEN] = "";
#else /* USE_LIBPFCTL */
#define RULE (pr.rule)
#endif /* USE_LIBPFCTL */
	UNUSED(ifname);

	if(dev<0) {
		syslog(LOG_ERR, "pf device is not open");
		return -1;
	}
	memset(&pr, 0, sizeof(pr));
	strlcpy(pr.anchor, anchor_name, MAXPATHLEN);
#ifndef PF_NEWSTYLE
	RULE.action = PF_RDR;
	pr.rule.action = PF_RDR;	/* used with USE_LIBPFCTL for the DIOCCHANGERULE calls */
#endif
#ifdef USE_LIBPFCTL
	if (pfctl_get_rules_info(dev, &ri, PF_RDR, anchor_name) < 0)
	{
		syslog(LOG_ERR, "pfctl_get_rules_info: %m");
		return -1;
	}
	pr.ticket = ri.ticket;
	n = ri.nr;
#else /* USE_LIBPFCTL */
	if(ioctl(dev, DIOCGETRULES, &pr) < 0)
	{
		syslog(LOG_ERR, "ioctl(dev, DIOCGETRULES, ...): %m");
		return -1;
	}
	n = pr.nr;
#ifdef PF_RELEASETICKETS
	tnum = pr.ticket;
#endif /* PF_RELEASETICKETS */
#endif /* USE_LIBPFCTL */
	r = -2;
	for(i=0; i<n; i++)
	{
#ifdef USE_LIBPFCTL
		if(pfctl_get_rule(dev, i, ri.ticket, anchor_name, PF_RDR, &rule, anchor_call) < 0)
#else /* USE_LIBPFCTL */
		pr.nr = i;
		if(ioctl(dev, DIOCGETRULE, &pr) < 0)
#endif /* USE_LIBPFCTL */
		{
			syslog(LOG_ERR, "ioctl(dev, DIOCGETRULE): %m");
			r = -1;
			break;
		}
#ifdef __APPLE__
		if( (eport == ntohs(RULE.dst.xport.range.port[0]))
		  && (eport == ntohs(RULE.dst.xport.range.port[1]))
#else
		if( (eport == ntohs(RULE.dst.port[0]))
		  && (eport == ntohs(RULE.dst.port[1]))
#endif
		  && (RULE.proto == proto) )
		{
			/* retrieve iport in order to remove filter rule */
#ifndef PF_NEWSTYLE
			if(iport) *iport = RULE.rpool.proxy_port[0];
			if(iaddr)
			{
				/* retrieve internal address */
				struct pfioc_pooladdr pp;
				memset(&pp, 0, sizeof(pp));
				strlcpy(pp.anchor, anchor_name, MAXPATHLEN);
				pp.r_action = PF_RDR;
				pp.r_num = i;
#ifdef USE_LIBPFCTL
				pp.ticket = ri.ticket;
#else /* USE_LIBPFCTL */
				pp.ticket = pr.ticket;
#endif /* USE_LIBPFCTL */
				if(ioctl(dev, DIOCGETADDRS, &pp) < 0)
				{
					syslog(LOG_ERR, "ioctl(dev, DIOCGETADDRS, ...): %m");
					r = -1;
					break;
				}
				if(pp.nr != 1)
				{
					syslog(LOG_NOTICE, "No address associated with pf rule");
					r = -1;
					break;
				}
				pp.nr = 0;	/* first */
				if(ioctl(dev, DIOCGETADDR, &pp) < 0)
				{
					syslog(LOG_ERR, "ioctl(dev, DIOCGETADDR, ...): %m");
					r = -1;
					break;
				}
#ifdef PFVAR_NEW_STYLE
				*iaddr = pp.addr.addr.v.a.addr.v4addr.s_addr;
#else
				*iaddr = pp.addr.addr.v.a.addr.v4.s_addr;
#endif
			}
#else
			if(iport) *iport = RULE.rdr.proxy_port[0];
			if(iaddr)
			{
				/* retrieve internal address */
				*iaddr = RULE.rdr.addr.v.a.addr.v4.s_addr;
			}
#endif
			if(rhost && rhostlen > 0)
			{
#ifdef PFVAR_NEW_STYLE
				if (RULE.src.addr.v.a.addr.v4addr.s_addr == 0)
#else
				if (RULE.src.addr.v.a.addr.v4.s_addr == 0)
#endif
					rhost[0] = '\0'; /* empty string */
				else
#ifdef PFVAR_NEW_STYLE
					inet_ntop(AF_INET, &RULE.src.addr.v.a.addr.v4addr.s_addr,
					          rhost, rhostlen);
#else
					inet_ntop(AF_INET, &RULE.src.addr.v.a.addr.v4.s_addr,
					          rhost, rhostlen);
#endif
			}
			if(check_desc) {
#ifdef USE_LIBPFCTL
				if((desc == NULL && RULE.label[0][0] == '\0') ||
				   (desc && 0 == strcmp(desc, RULE.label[0]))) {
#else /* USE_LIBPFCTL */
				if((desc == NULL && RULE.label[0] == '\0') ||
				   (desc && 0 == strcmp(desc, RULE.label))) {
#endif /* USE_LIBPFCTL */
					r = 1;
					break;
				}
			}
			pr.action = PF_CHANGE_GET_TICKET;
        	if(ioctl(dev, DIOCCHANGERULE, &pr) < 0)
			{
            	syslog(LOG_ERR, "ioctl(dev, DIOCCHANGERULE, ...) PF_CHANGE_GET_TICKET: %m");
				r = -1;
				break;
			}
			pr.action = PF_CHANGE_REMOVE;
			pr.nr = i;
			if(ioctl(dev, DIOCCHANGERULE, &pr) < 0)
			{
				syslog(LOG_ERR, "ioctl(dev, DIOCCHANGERULE, ...) PF_CHANGE_REMOVE: %m");
				r = -1;
				break;
			}
			remove_timestamp_entry(eport, proto);
			r = 0;
			break;
		}
	}
	if (r == -2 && !quiet_not_found)
		syslog(LOG_NOTICE, "could not find redirect rule to delete eport=%hu", eport);
	release_ticket(dev, tnum);
	return r;
}

/* delete another rule of a mapping which has several (PCP FILTER) */
static int
priv_delete_redirect_rule_quiet(const char * ifname, unsigned short eport,
                                int proto)
{
	int r;
	quiet_not_found = 1;
	r = priv_delete_redirect_rule(ifname, eport, proto, NULL, NULL, NULL, 0);
	quiet_not_found = 0;
	return r;
}

int
delete_redirect_rule(const char * ifname, unsigned short eport,
                    int proto)
{
	int r;
	r = priv_delete_redirect_rule(ifname, eport, proto, NULL, NULL, NULL, 0);
	/* a filtered PCP mapping has a rule per allowed peer */
	while(r == 0 && priv_delete_redirect_rule_quiet(ifname, eport, proto) == 0)
		;
	return r;
}

/* when active, priv_delete_filter_rule() only removes the rule having this
 * source (used for the rules of a PCP FILTER policy) */
static struct {
	int active;
	in_addr_t addr;
	unsigned int prefix;
	unsigned short port;
} filter_src_match;

/* returns:  0 : OK
 *          -1 : Error
 *          -2 : rule not found */
static int
priv_delete_filter_rule(const char * ifname, unsigned short iport,
                        int proto, in_addr_t iaddr)
{
#ifndef PF_ENABLE_FILTER_RULES
	UNUSED(ifname); UNUSED(iport); UNUSED(proto); UNUSED(iaddr);
	return 0;
#else
	int i, n, r;
	unsigned int tnum;
	struct pfioc_rule pr;
	UNUSED(ifname);
	if(dev<0) {
		syslog(LOG_ERR, "pf device is not open");
		return -1;
	}
	memset(&pr, 0, sizeof(pr));
	strlcpy(pr.anchor, anchor_name, MAXPATHLEN);
	RULE.action = PF_PASS;
	if(ioctl(dev, DIOCGETRULES, &pr) < 0)
	{
		syslog(LOG_ERR, "ioctl(dev, DIOCGETRULES, ...): %m");
		return -1;
	}
	n = pr.nr;
#ifdef PF_RELEASETICKETS
	tnum = pr.ticket;
#endif /* PF_RELEASETICKETS */
	r = -2;
	for(i=0; i<n; i++)
	{
		pr.nr = i;
		if(ioctl(dev, DIOCGETRULE, &pr) < 0)
		{
			syslog(LOG_ERR, "ioctl(dev, DIOCGETRULE): %m");
			r = -1;
			break;
		}
#ifdef TEST
syslog(LOG_DEBUG, "%2d port=%hu proto=%d addr=%8x",
       i, ntohs(RULE.dst.port[0]), RULE.proto,
       RULE.dst.addr.v.a.addr.v4.s_addr);
/*RULE.dst.addr.v.a.mask.v4.s_addr*/
#endif
		if( (iport == ntohs(RULE.dst.port[0]))
		  && (RULE.proto == proto) &&
		   (iaddr == 0 || iaddr == RULE.dst.addr.v.a.addr.v4.s_addr) &&
		   (!filter_src_match.active ||
		    (RULE.src.addr.v.a.addr.v4.s_addr ==
		         (filter_src_match.addr & prefix_to_mask4(filter_src_match.prefix))
		     && RULE.src.addr.v.a.mask.v4.s_addr ==
		         prefix_to_mask4(filter_src_match.prefix)
		     && (RULE.src.port_op == PF_OP_EQ ?
		         ntohs(RULE.src.port[0]) : 0) == filter_src_match.port))
		  )
		{
			pr.action = PF_CHANGE_GET_TICKET;
        	if(ioctl(dev, DIOCCHANGERULE, &pr) < 0)
			{
            	syslog(LOG_ERR, "ioctl(dev, DIOCCHANGERULE, ...) PF_CHANGE_GET_TICKET: %m");
				r = -1;
				break;
			}
			pr.action = PF_CHANGE_REMOVE;
			pr.nr = i;
			if(ioctl(dev, DIOCCHANGERULE, &pr) < 0)
			{
				syslog(LOG_ERR, "ioctl(dev, DIOCCHANGERULE, ...) PF_CHANGE_REMOVE: %m");
				r = -1;
			}
			else
			{
				r = 0;
			}
			break;
		}
	}
	if (r == -2)
		syslog(LOG_NOTICE, "could not find filter rule to delete iport=%hu addr=%8x", iport, ntohl(iaddr));
	release_ticket(dev, tnum);
	return r;
#endif
}

/* returns:  0 : OK
 *          -1 : Error
 *          -2 : rule not found */
int
delete_filter_rule(const char * ifname, unsigned short port, int proto)
{
	return priv_delete_filter_rule(ifname, port, proto, 0);
}

/* returns:  0 : OK
 *          -1 : Error
 *          -2 : rule not found */
int
delete_redirect_and_filter_rules(const char * ifname, unsigned short eport,
                                 int proto)
{
	int r;
	unsigned short iport;
	in_addr_t iaddr;
	int n = 1;
	r = priv_delete_redirect_rule(ifname, eport, proto, &iport, &iaddr, NULL, 0);
	if(r == 0)
	{
		/* a filtered PCP mapping has a rule per allowed peer */
		while(priv_delete_redirect_rule_quiet(ifname, eport, proto) == 0)
			n++;
#ifdef ENABLE_PORT_TRIGGERING
		if (proto == IPPROTO_UDP) {
			delete_nat_rule(ifname, eport, iport, proto, iaddr);
		}
#endif
		r = priv_delete_filter_rule(ifname, iport, proto, iaddr);
		while(--n > 0)
			priv_delete_filter_rule(ifname, iport, proto, iaddr);
	}
	return r;
}

/* source restriction of the rule returned by the last successful call
 * to get_redirect_rule_by_index() */
static in_addr_t last_rdr_src_addr;
static unsigned int last_rdr_src_prefix;
static unsigned short last_rdr_src_port;

int
get_redirect_rule_by_index(int index,
                           char * ifname, unsigned short * eport,
                           char * iaddr, int iaddrlen, unsigned short * iport,
                           int * proto, char * desc, int desclen,
                           char * rhost, int rhostlen,
                           unsigned int * timestamp,
                           u_int64_t * packets, u_int64_t * bytes)
{
	int n, r;
	unsigned int tnum;
#ifdef USE_LIBPFCTL
	struct pfctl_rules_info ri;
	struct pfctl_rule rule;
#define RULE (rule)
	char anchor_call[MAXPATHLEN] = "";
#else /* USE_LIBPFCTL */
	struct pfioc_rule pr;
#define RULE (pr.rule)
#endif /* USE_LIBPFCTL */
#ifndef PF_NEWSTYLE
	struct pfioc_pooladdr pp;
#endif
	if(index < 0)
		return -1;
	if(dev<0) {
		syslog(LOG_ERR, "pf device is not open");
		return -1;
	}
#ifdef USE_LIBPFCTL
	if(pfctl_get_rules_info(dev, &ri, PF_RDR, anchor_name) < 0)
	{
		syslog(LOG_ERR, "pfctl_get_rules_info: %m");
		return -1;
	}
	n = ri.nr;
#else /* USE_LIBPFCTL */
	memset(&pr, 0, sizeof(pr));
	strlcpy(pr.anchor, anchor_name, MAXPATHLEN);
#ifndef PF_NEWSTYLE
	RULE.action = PF_RDR;
#endif
	if(ioctl(dev, DIOCGETRULES, &pr) < 0)
	{
		syslog(LOG_ERR, "ioctl(dev, DIOCGETRULES, ...): %m");
		return -1;
	}
	n = pr.nr;
#ifdef PF_RELEASETICKETS
	tnum = pr.ticket;
#endif /* PF_RELEASETICKETS */
#endif /* USE_LIBPFCTL */
	r = -1;
	if(index >= n)
		goto error;
#ifdef USE_LIBPFCTL
	if(pfctl_get_rule(dev, index, ri.ticket, anchor_name, PF_RDR, &rule, anchor_call) < 0)
	{
		syslog(LOG_ERR, "pfctl_get_rule: %m");
		goto error;
	}
#else /* USE_LIBPFCTL */
#if defined(OpenBSD) && OpenBSD >= 202310
	/* OpenBSD >= 7.4
	 * DIOCGETRULE is changed to always get rules incrementaly
	 * pr.nr is now a return value
	 * https://github.com/openbsd/src/commit/072583c99019a91ac511a1e33e10ad02df79ec97 */
	do {
		if(ioctl(dev, DIOCGETRULE, &pr) < 0)
		{
			syslog(LOG_ERR, "ioctl(dev, DIOCGETRULE): %m");
			goto error;
		}
	} while(pr.nr < (unsigned int)index);
#else
	/* not OpenBSD >= 7.4 */
	pr.nr = index;
	if(ioctl(dev, DIOCGETRULE, &pr) < 0)
	{
		syslog(LOG_ERR, "ioctl(dev, DIOCGETRULE): %m");
		goto error;
	}
#endif /* defined(OpenBSD) && OpenBSD >= 202310 */
#endif /* USE_LIBPFCTL */
	*proto = RULE.proto;
#ifdef __APPLE__
	*eport = ntohs(RULE.dst.xport.range.port[0]);
#else
	*eport = ntohs(RULE.dst.port[0]);
#endif
#ifndef PF_NEWSTYLE
	*iport = RULE.rpool.proxy_port[0];
#else
	*iport = RULE.rdr.proxy_port[0];
#endif
	if(ifname)
		strlcpy(ifname, RULE.ifname, IFNAMSIZ);
	if(desc)
#ifdef USE_LIBPFCTL
		strlcpy(desc, RULE.label[0], desclen);
#else /* USE_LIBPFCTL */
		strlcpy(desc, RULE.label, desclen);
#endif /* USE_LIBPFCTL */
#ifdef PFRULE_INOUT_COUNTS
	if(packets)
		*packets = RULE.packets[0] + RULE.packets[1];
	if(bytes)
		*bytes = RULE.bytes[0] + RULE.bytes[1];
#else
	if(packets)
		*packets = RULE.packets;
	if(bytes)
		*bytes = RULE.bytes;
#endif
#ifndef PF_NEWSTYLE
	memset(&pp, 0, sizeof(pp));
	strlcpy(pp.anchor, anchor_name, MAXPATHLEN);
	pp.r_action = PF_RDR;
	pp.r_num = index;
#ifdef USE_LIBPFCTL
	pp.ticket = ri.ticket;
#else /* USE_LIBPFCTL */
	pp.ticket = pr.ticket;
#endif /* USE_LIBPFCTL */
	if(ioctl(dev, DIOCGETADDRS, &pp) < 0)
	{
		syslog(LOG_ERR, "ioctl(dev, DIOCGETADDRS, ...): %m");
		goto error;
	}
	if(pp.nr != 1)
	{
		syslog(LOG_NOTICE, "No address associated with pf rule");
		goto error;
	}
	pp.nr = 0;	/* first */
	if(ioctl(dev, DIOCGETADDR, &pp) < 0)
	{
		syslog(LOG_ERR, "ioctl(dev, DIOCGETADDR, ...): %m");
		goto error;
	}
#ifdef PFVAR_NEW_STYLE
	inet_ntop(AF_INET, &pp.addr.addr.v.a.addr.v4addr.s_addr,
	          iaddr, iaddrlen);
#else
	inet_ntop(AF_INET, &pp.addr.addr.v.a.addr.v4.s_addr,
	          iaddr, iaddrlen);
#endif
#else
	inet_ntop(AF_INET, &RULE.rdr.addr.v.a.addr.v4.s_addr,
	          iaddr, iaddrlen);
#endif
	if(rhost && rhostlen > 0)
	{
#ifdef PFVAR_NEW_STYLE
		if (RULE.src.addr.v.a.addr.v4addr.s_addr == 0)
#else
		if (RULE.src.addr.v.a.addr.v4.s_addr == 0)
#endif
		{
			rhost[0] = '\0'; /* empty string */
		}
		else
		{
#ifdef PFVAR_NEW_STYLE
			inet_ntop(AF_INET, &RULE.src.addr.v.a.addr.v4addr.s_addr,
			          rhost, rhostlen);
#else
			inet_ntop(AF_INET, &RULE.src.addr.v.a.addr.v4.s_addr,
			          rhost, rhostlen);
#endif
		}
	}
	if(timestamp)
		*timestamp = get_timestamp(*eport, *proto);
	/* source restriction of the rule, used by the PCP FILTER code */
	{
		in_addr_t m;
#ifdef PFVAR_NEW_STYLE
		m = RULE.src.addr.v.a.mask.v4addr.s_addr;
		last_rdr_src_addr = RULE.src.addr.v.a.addr.v4addr.s_addr;
#else
		m = RULE.src.addr.v.a.mask.v4.s_addr;
		last_rdr_src_addr = RULE.src.addr.v.a.addr.v4.s_addr;
#endif
		last_rdr_src_prefix = 0;
		m = ntohl(m);
		while(m & 0x80000000U) { last_rdr_src_prefix++; m <<= 1; }
		if(last_rdr_src_addr == 0)
			last_rdr_src_prefix = 0;
#ifdef __APPLE__
		last_rdr_src_port = RULE.src.xport.range.op == PF_OP_EQ ?
		                    ntohs(RULE.src.xport.range.port[0]) : 0;
#else
		last_rdr_src_port = RULE.src.port_op == PF_OP_EQ ?
		                    ntohs(RULE.src.port[0]) : 0;
#endif
	}
	r = 0;
error:
	release_ticket(dev, tnum);
	return r;
}

/* return an (malloc'ed) array of "external" port for which there is
 * a port mapping. number is the size of the array */
unsigned short *
get_portmappings_in_range(unsigned short startport, unsigned short endport,
                          int proto, unsigned int * number)
{
	unsigned short * array;
	unsigned int capacity, tnum;
	int i, n;
	unsigned short eport;
#ifdef USE_LIBPFCTL
	struct pfctl_rules_info ri;
	struct pfctl_rule rule;
#define RULE (rule)
#else /* USE_LIBPFCTL */
	struct pfioc_rule pr;
#define RULE (pr.rule)
#endif

	*number = 0;
	if(dev<0) {
		syslog(LOG_ERR, "pf device is not open");
		return NULL;
	}
	capacity = 128;
	array = calloc(capacity, sizeof(unsigned short));
	if(!array)
	{
		syslog(LOG_ERR, "get_portmappings_in_range() : calloc error");
		return NULL;
	}
#ifdef USE_LIBPFCTL
	if (pfctl_get_rules_info(dev, &ri, PF_RDR, anchor_name) < 0)
	{
		syslog(LOG_ERR, "pfctl_get_rules_info: %m");
		free(array);
		return NULL;
	}
	n = ri.nr;
#else /* USE_LIBPFCTL */
	memset(&pr, 0, sizeof(pr));
	strlcpy(pr.anchor, anchor_name, MAXPATHLEN);
#ifndef PF_NEWSTYLE
	RULE.action = PF_RDR;
#endif
	if(ioctl(dev, DIOCGETRULES, &pr) < 0)
	{
		syslog(LOG_ERR, "ioctl(dev, DIOCGETRULES, ...): %m");
		free(array);
		return NULL;
	}
	n = pr.nr;
#ifdef PF_RELEASETICKETS
	tnum = pr.ticket;
#endif /* PF_RELEASETICKETS */
#endif /* USE_LIBPFCTL */
	for(i=0; i<n; i++)
	{
#ifdef USE_LIBPFCTL
#else /* USE_LIBPFCTL */
		pr.nr = i;
		if(ioctl(dev, DIOCGETRULE, &pr) < 0)
		{
			syslog(LOG_ERR, "ioctl(dev, DIOCGETRULE): %m");
			continue;
		}
#endif /* USE_LIBPFCTL */
#ifdef __APPLE__
		eport = ntohs(RULE.dst.xport.range.port[0]);
		if( (eport == ntohs(RULE.dst.xport.range.port[1]))
#else
		eport = ntohs(RULE.dst.port[0]);
		if( (eport == ntohs(RULE.dst.port[1]))
#endif
		  && (RULE.proto == proto)
		  && (startport <= eport) && (eport <= endport) )
		{
			if(*number >= capacity)
			{
				/* need to increase the capacity of the array */
				unsigned short * tmp;
				capacity += 128;
				tmp = realloc(array, sizeof(unsigned short)*capacity);
				if(!tmp)
				{
					syslog(LOG_ERR, "get_portmappings_in_range() : realloc(%lu) error", sizeof(unsigned short)*capacity);
					*number = 0;
					free(array);
					release_ticket(dev, tnum);
					return NULL;
				}
				array = tmp;
			}
			array[*number] = eport;
			(*number)++;
		}
	}
	release_ticket(dev, tnum);
	return array;
}

/* update the port mapping internal port, description and timestamp
 * returns:  0 : OK
 *          -1 : Error */
int
update_portmapping(const char * ifname, unsigned short eport, int proto,
                   unsigned short iport, const char * desc,
                   unsigned int timestamp)
{
	unsigned short old_iport;
	in_addr_t iaddr;
	char iaddr_str[16];
	char rhost[32];

	if(priv_delete_redirect_rule(ifname, eport, proto, &old_iport, &iaddr, rhost, sizeof(rhost)) < 0)
		return -1;
	if (priv_delete_filter_rule(ifname, old_iport, proto, iaddr) < 0)
		return -1;

	if (inet_ntop(AF_INET, &iaddr, iaddr_str, sizeof(iaddr_str)) == NULL) {
		syslog(LOG_ERR, "inet_ntop(AF_INET, ...): %m");
		return -1;
	}

	if(add_redirect_rule2(ifname, rhost, eport, iaddr_str, iport, proto,
	                      desc, timestamp) < 0)
		return -1;
	if(add_filter_rule2(ifname, rhost, iaddr_str, eport, iport, proto, desc) < 0)
		return -1;

	return 0;
}

/* update the port mapping description and timestamp */
int
update_portmapping_desc_timestamp(const char * ifname,
                   unsigned short eport, int proto,
                   const char * desc, unsigned int timestamp)
{
	unsigned short iport;
	in_addr_t iaddr;
	char iaddr_str[16];
	char rhost[32];
	int r;

	r = priv_delete_redirect_rule_check_desc(ifname, eport, proto, &iport, &iaddr, rhost, sizeof(rhost), 1, desc);
	if(r < 0)
		return -1;
	if(r == 1) {
		/* only change timestamp */
		remove_timestamp_entry(eport, proto);
		add_timestamp_entry(eport, proto, timestamp);
		return 0;
	}
	if (priv_delete_filter_rule(ifname, iport, proto, iaddr) < 0)
		return -1;

	if (inet_ntop(AF_INET, &iaddr, iaddr_str, sizeof(iaddr_str)) == NULL) {
		syslog(LOG_ERR, "inet_ntop(AF_INET, ...): %m");
		return -1;
	}

	if(add_redirect_rule2(ifname, rhost, eport, iaddr_str, iport, proto,
	                      desc, timestamp) < 0)
		return -1;
	if(add_filter_rule2(ifname, rhost, iaddr_str, eport, iport, proto, desc) < 0)
		return -1;

	return 0;
}


/* this function is only for testing */
#if TEST
void
list_rules(void)
{
	char buf[32];
	char buf2[32];
	int i, n;
	unsigned int tnum;
#ifdef USE_LIBPFCTL
	struct pfctl_rules_info ri;
	struct pfctl_rule rule;
#define RULE (rule)
	char anchor_call[MAXPATHLEN] = "";
#else /* USE_LIBPFCTL */
	struct pfioc_rule pr;
#define RULE (pr.rule)
#endif /* USE_LIBPFCTL */
#ifndef PF_NEWSTYLE
	struct pfioc_pooladdr pp;
#endif

	if(dev<0)
	{
		perror("pf dev not open");
		return ;
	}

#ifdef USE_LIBPFCTL
	if (pfctl_get_rules_info(dev, &ri, PF_RDR, anchor_name) < 0)
		perror("pfctl_get_rules_info");
	printf("ticket = %d, nr = %d\n", ri.ticket, ri.nr);
	n = ri.nr;
#else /* USE_LIBPFCTL */
	memset(&pr, 0, sizeof(pr));
	strlcpy(pr.anchor, anchor_name, MAXPATHLEN);
	RULE.action = PF_RDR;
	if(ioctl(dev, DIOCGETRULES, &pr) < 0)
		perror("DIOCGETRULES");
	printf("ticket = %d, nr = %d\n", pr.ticket, pr.nr);
	n = pr.nr;
#endif /* USE_LIBPFCTL */
	for(i=0; i<n; i++)
	{
		printf("-- rule %d --\n", i);
#ifdef USE_LIBPFCTL
		if(pfctl_get_rule(dev, i, ri.ticket, anchor_name, PF_RDR, &rule, anchor_call) < 0)
			perror("pfctl_get_rule");
#else /* USE_LIBPFCTL */
		pr.nr = i;
		if(ioctl(dev, DIOCGETRULE, &pr) < 0)
			perror("DIOCGETRULE");
#endif /* USE_LIBPFCTL */
		printf(" %s %s %d:%d -> %s %d:%d  proto %d keep_state=%d action=%d\n",
			RULE.ifname,
			inet_ntop(AF_INET, &RULE.src.addr.v.a.addr.v4.s_addr, buf, 32),
			(int)ntohs(RULE.dst.port[0]),
			(int)ntohs(RULE.dst.port[1]),
			inet_ntop(AF_INET, &RULE.dst.addr.v.a.addr.v4.s_addr, buf2, 32),
#ifndef PF_NEWSTYLE
			(int)RULE.rpool.proxy_port[0],
			(int)RULE.rpool.proxy_port[1],
#else
			(int)RULE.rdr.proxy_port[0],
			(int)RULE.rdr.proxy_port[1],
#endif
			(int)RULE.proto,
			(int)RULE.keep_state,
			(int)RULE.action);
#ifdef USE_LIBPFCTL
		printf("  description: \"%s\"\n", RULE.label[0]);
#else /* USE_LIBPFCTL */
		printf("  description: \"%s\"\n", RULE.label);
#endif /* USE_LIBPFCTL */
#ifndef PF_NEWSTYLE
		memset(&pp, 0, sizeof(pp));
		strlcpy(pp.anchor, anchor_name, MAXPATHLEN);
		pp.r_action = PF_RDR;
		pp.r_num = i;
#ifdef USE_LIBPFCTL
		pp.ticket = ri.ticket;
#else
		pp.ticket = pr.ticket;
#endif
		if(ioctl(dev, DIOCGETADDRS, &pp) < 0)
			perror("DIOCGETADDRS");
		printf("  nb pool addr = %d ticket=%d\n", pp.nr, pp.ticket);
		/*if(ioctl(dev, DIOCGETRULE, &pr) < 0)
			perror("DIOCGETRULE"); */
		pp.nr = 0;	/* first */
		if(ioctl(dev, DIOCGETADDR, &pp) < 0)
			perror("DIOCGETADDR");
		/* addr.v.a.addr.v4.s_addr */
		printf("  %s\n", inet_ntop(AF_INET, &pp.addr.addr.v.a.addr.v4.s_addr, buf, 32));
#else
		printf("  rule_flag=%08x action=%d direction=%d log=%d logif=%d "
		       "quick=%d ifnot=%d af=%d type=%d code=%d rdr.port_op=%d rdr.opts=%d\n",
		       RULE.rule_flag, RULE.action, RULE.direction,
		       RULE.log, RULE.logif, RULE.quick, RULE.ifnot,
		       RULE.af, RULE.type, RULE.code,
		       RULE.rdr.port_op, RULE.rdr.opts);
		printf("  %s\n", inet_ntop(AF_INET, &RULE.rdr.addr.v.a.addr.v4.s_addr, buf, 32));
#endif
	}
	release_ticket(dev, tnum);
}
#endif /* TEST */


/* ---- PCP MAP FILTER policy ---- */
struct pf_group_template {
	unsigned short eport;
	char desc[PF_RULE_LABEL_SIZE];
	char ifname[IFNAMSIZ];
	unsigned int nrules;
};

struct pcp_filter_update {
	int existing;	/* the mapping already existed (its rules were rewritten) */
	int v6;		/* IPv6 mapping (pinholes) */
	struct pf_pcp_policy old;
};

/* remove the rdr rule at this index */
static int
remove_rdr_rule_at(int index)
{
	struct pfioc_rule pr;
	unsigned int tnum = 0;
	int r = -1;
#ifdef USE_LIBPFCTL
	struct pfctl_rules_info ri;
#endif
	if(dev<0)
		return -1;
	memset(&pr, 0, sizeof(pr));
	strlcpy(pr.anchor, anchor_name, MAXPATHLEN);
#ifndef PF_NEWSTYLE
	pr.rule.action = PF_RDR;
#endif
#ifdef USE_LIBPFCTL
	if(pfctl_get_rules_info(dev, &ri, PF_RDR, anchor_name) < 0)
	{
		syslog(LOG_ERR, "pfctl_get_rules_info: %m");
		return -1;
	}
	pr.ticket = ri.ticket;
#ifdef PF_RELEASETICKETS
	tnum = ri.ticket;
#endif
#else
	if(ioctl(dev, DIOCGETRULES, &pr) < 0)
	{
		syslog(LOG_ERR, "ioctl(dev, DIOCGETRULES, ...): %m");
		return -1;
	}
#ifdef PF_RELEASETICKETS
	tnum = pr.ticket;
#endif
#endif
	pr.action = PF_CHANGE_GET_TICKET;
	if(ioctl(dev, DIOCCHANGERULE, &pr) < 0)
	{
		syslog(LOG_ERR, "ioctl(dev, DIOCCHANGERULE, ...) PF_CHANGE_GET_TICKET: %m");
		goto end;
	}
	pr.action = PF_CHANGE_REMOVE;
	pr.nr = index;
	if(ioctl(dev, DIOCCHANGERULE, &pr) < 0)
	{
		syslog(LOG_ERR, "ioctl(dev, DIOCCHANGERULE, ...) PF_CHANGE_REMOVE: %m");
		goto end;
	}
	r = 0;
end:
	release_ticket(dev, tnum);
	return r;
}

static void
policy_iaddr_str(const struct in6_addr * address, char * buf, size_t len)
{
	inet_ntop(AF_INET, address->s6_addr + 12, buf, len);
}

/* read the rules of a mapping : the policy and the parameters of its rules.
 * returns the number of rules */
static unsigned int
read_group(const struct in6_addr * address, unsigned short port,
           unsigned char protocol,
           struct pf_pcp_policy * policy, struct pf_group_template * tpl)
{
	char want[INET_ADDRSTRLEN], iaddr[INET_ADDRSTRLEN];
	char ifname[IFNAMSIZ], desc[PF_RULE_LABEL_SIZE];
	unsigned short eport, iport;
	int i, proto;
	memset(policy, 0, sizeof(*policy));
	memset(tpl, 0, sizeof(*tpl));
	policy->address = *address;
	policy->port = port;
	policy->protocol = protocol;
	policy_iaddr_str(address, want, sizeof(want));
	for(i = 0; get_redirect_rule_by_index(i, ifname, &eport, iaddr, sizeof(iaddr),
	                                      &iport, &proto, desc, sizeof(desc),
	                                      NULL, 0, NULL, NULL, NULL) == 0; i++)
	{
		if(iport != port || proto != protocol || strcmp(iaddr, want) != 0)
			continue;
		if(tpl->nrules++ == 0)
		{
			tpl->eport = eport;
			strlcpy(tpl->desc, desc, sizeof(tpl->desc));
			strlcpy(tpl->ifname, ifname, sizeof(tpl->ifname));
		}
		if(last_rdr_src_prefix > 0 && policy->count < PCP_FILTER_PEER_MAX)
		{
			struct pcp_filter * f = &policy->filters[policy->count++];
			memset(&f->address, 0, sizeof(f->address));
			f->address.s6_addr[10] = f->address.s6_addr[11] = 0xff;
			memcpy(f->address.s6_addr + 12, &last_rdr_src_addr, 4);
			f->prefix = last_rdr_src_prefix + 96;
			f->port = last_rdr_src_port;
		}
	}
	return tpl->nrules;
}

struct src_entry {
	in_addr_t addr;	/* network byte order */
	unsigned int prefix;
	unsigned short port;
};

/* k-th source of the rules of a policy (the unfiltered rule if no filter) */
static void
policy_entry(const struct pf_pcp_policy * policy, unsigned int k,
             struct src_entry * e)
{
	memset(e, 0, sizeof(*e));
	if(policy->count)
	{
		memcpy(&e->addr, policy->filters[k].address.s6_addr + 12, 4);
		e->prefix = policy->filters[k].prefix - 96;
		e->port = policy->filters[k].port;
	}
}

static int
policy_has_entry(const struct pf_pcp_policy * policy, const struct src_entry * e)
{
	unsigned int k, n = policy->count ? policy->count : 1;
	struct src_entry o;
	for(k = 0; k < n; k++)
	{
		policy_entry(policy, k, &o);
		if(o.prefix == e->prefix && o.port == e->port &&
		   (o.addr & prefix_to_mask4(o.prefix)) == (e->addr & prefix_to_mask4(e->prefix)))
			return 1;
	}
	return 0;
}

/* remove the rdr rule of the mapping having this source */
static int
remove_group_rule(const struct in6_addr * address, unsigned short port,
                  unsigned char protocol, const struct src_entry * e)
{
	char want[INET_ADDRSTRLEN], iaddr[INET_ADDRSTRLEN];
	unsigned short eport, iport;
	int i, proto;
	policy_iaddr_str(address, want, sizeof(want));
	for(i = 0; get_redirect_rule_by_index(i, NULL, &eport, iaddr, sizeof(iaddr),
	                                      &iport, &proto, NULL, 0,
	                                      NULL, 0, NULL, NULL, NULL) == 0; i++)
	{
		if(iport == port && proto == protocol && strcmp(iaddr, want) == 0 &&
		   last_rdr_src_prefix == e->prefix && last_rdr_src_port == e->port &&
		   (last_rdr_src_addr & prefix_to_mask4(e->prefix)) ==
		       (e->addr & prefix_to_mask4(e->prefix)))
			return remove_rdr_rule_at(i);
	}
	return -1;
}

/* change the rules of a mapping from the policy 'from' to the policy 'to' :
 * the missing rules are added first, then the obsolete ones are removed */
static int
group_apply(const struct pf_pcp_policy * to, const struct pf_pcp_policy * from,
            const struct pf_group_template * tpl)
{
	char iaddr[INET_ADDRSTRLEN];
	unsigned int k, n;
	struct src_entry e;
	struct in_addr a;
	int r = 0;
	policy_iaddr_str(&to->address, iaddr, sizeof(iaddr));
	n = to->count ? to->count : 1;
	for(k = 0; k < n && r == 0; k++)
	{
		policy_entry(to, k, &e);
		if(policy_has_entry(from, &e))
			continue;
		r = add_redirect_rule_ex(tpl->ifname, e.addr, e.prefix, e.port, tpl->eport,
		                         iaddr, to->port, to->protocol, tpl->desc);
		if(r == 0)
			r = add_filter_rule_ex(tpl->ifname, e.addr, e.prefix, e.port, iaddr,
			                       tpl->eport, to->port, to->protocol, tpl->desc);
	}
	if(r < 0)
		return -1;
	n = from->count ? from->count : 1;
	for(k = 0; k < n; k++)
	{
		policy_entry(from, k, &e);
		if(policy_has_entry(to, &e))
			continue;
		remove_group_rule(&to->address, to->port, to->protocol, &e);
		inet_pton(AF_INET, iaddr, &a);
		filter_src_match.active = 1;
		filter_src_match.addr = e.addr;
		filter_src_match.prefix = e.prefix;
		filter_src_match.port = e.port;
		priv_delete_filter_rule(tpl->ifname, to->port, to->protocol, a.s_addr);
		filter_src_match.active = 0;
	}
	return 0;
}

/* ---- IPv6 : the policy is stored in the pinholes of the mapping ---- */
#ifdef ENABLE_UPNPPINHOLE
static void
mask6(struct in6_addr * a, unsigned int prefix)
{
	unsigned int i;
	for(i = 0; i < 16; i++, prefix = prefix >= 8 ? prefix - 8 : 0)
		a->s6_addr[i] &= prefix >= 8 ? 255 : (255 << (8 - prefix)) & 255;
}

/* f == NULL is the unfiltered pinhole */
static int
policy6_has_entry(const struct pf_pcp_policy * policy, const struct pcp_filter * f)
{
	unsigned int k;
	struct in6_addr a, b;
	if(policy->count == 0)
		return f == NULL;
	if(f == NULL)
		return 0;
	a = f->address;
	mask6(&a, f->prefix);
	for(k = 0; k < policy->count; k++)
	{
		b = policy->filters[k].address;
		mask6(&b, policy->filters[k].prefix);
		if(policy->filters[k].prefix == f->prefix &&
		   policy->filters[k].port == f->port && memcmp(&a, &b, sizeof(a)) == 0)
			return 1;
	}
	return 0;
}

static int
group_apply6(const struct pf_pcp_policy * to, const struct pf_pcp_policy * from,
             const char * ifname, const char * desc, unsigned int timestamp)
{
	unsigned int k, n;
	const struct pcp_filter * f;
	n = to->count ? to->count : 1;
	for(k = 0; k < n; k++)
	{
		f = to->count ? &to->filters[k] : NULL;
		if(policy6_has_entry(from, f))
			continue;
		if(pf_pinhole_group_add(ifname, &to->address, to->port, to->protocol,
		                        desc, timestamp, f) < 0)
			return -1;
	}
	n = from->count ? from->count : 1;
	for(k = 0; k < n; k++)
	{
		f = from->count ? &from->filters[k] : NULL;
		if(policy6_has_entry(to, f))
			continue;
		pf_pinhole_group_remove(&to->address, to->port, to->protocol, f);
	}
	return 0;
}

#endif /* ENABLE_UPNPPINHOLE */

/* merge the options of a request in a policy (RFC 6887 section 13.3) :
 * a FILTER with a prefix length of 0 removes all the peers.
 * returns 0, -1 (invalid) or -2 (too many peers) */
static int
policy_merge(struct pf_pcp_policy * p, const struct pcp_filter * filters,
             unsigned int count, int v4)
{
	unsigned int i, j, bits;
	struct pcp_filter f;
	for(i = 0; i < count; i++)
	{
		if(!filters[i].prefix)
		{
			p->count = 0;
			continue;
		}
		f = filters[i];
		if(v4 ? (!IN6_IS_ADDR_V4MAPPED(&f.address) || f.prefix < 96) :
		       (IN6_IS_ADDR_V4MAPPED(&f.address) || f.prefix > 128))
			return -1;
		/* canonicalize the unused suffix bits before deduplicating */
		bits = f.prefix;
		for(j = 0; j < sizeof(f.address.s6_addr); ++j)
		{
			f.address.s6_addr[j] &= bits >= 8 ? 255 : bits ? 255 << (8 - bits) : 0;
			bits = bits >= 8 ? bits - 8 : 0;
		}
		for(j = 0; j < p->count; ++j)
		{
			if(p->filters[j].prefix == f.prefix && p->filters[j].port == f.port &&
			   memcmp(&p->filters[j].address, &f.address, sizeof(f.address)) == 0)
				break;
		}
		if(j != p->count)
			continue;
		if(p->count == PCP_FILTER_PEER_MAX)
			return -2;
		p->filters[p->count++] = f;
	}
	return 0;
}

/* returns 0 : OK
 *        -1 : error
 *        -2 : too many peers
 *        -3 : not supported (IPv6 address) */
int
pf_pcp_filter_begin(const struct in6_addr * address, unsigned short port,
                    unsigned char protocol, const char * ifname,
                    const struct pcp_filter * filters, unsigned int count,
                    struct pcp_filter_update ** update)
{
	struct pcp_filter_update * u;
	struct pf_pcp_policy * merged;
	struct pf_group_template tpl;
	int r;
	UNUSED(ifname);
	*update = NULL;
	u = calloc(1, sizeof(*u));
	merged = calloc(1, sizeof(*merged));
	if(u == NULL || merged == NULL)
	{
		free(u);
		free(merged);
		return -1;
	}
	if(!IN6_IS_ADDR_V4MAPPED(address))
	{
#ifndef ENABLE_UPNPPINHOLE
		free(u);
		free(merged);
		return -3;
	}
	if(0)
	{
#else
		char desc[PF_RULE_LABEL_SIZE], ifn[IFNAMSIZ];
		unsigned int ts = 0;
		u->v6 = 1;
		memset(&u->old, 0, sizeof(u->old));
		u->old.address = *address;
		u->old.port = port;
		u->old.protocol = protocol;
		u->existing = pf_pinhole_group_get(address, port, protocol,
		                  u->old.filters, PCP_FILTER_PEER_MAX, &u->old.count,
		                  desc, sizeof(desc), &ts, ifn) > 0;
		*merged = u->old;
		r = policy_merge(merged, filters, count, 0);
		if(r == 0 && u->existing)
			r = group_apply6(merged, &u->old, ifn, desc, ts);
		if(r < 0)
		{
			free(u);
			free(merged);
			return r == -2 ? -2 : -1;
		}
		if(u->existing)
		{
			free(merged);
		}
		else
		{
			free(pending_policy);
			pending_policy = merged;
		}
		*update = u;
		return 0;
#endif /* ENABLE_UPNPPINHOLE */
	}
	u->existing = read_group(address, port, protocol, &u->old, &tpl) > 0;
	*merged = u->old;
	r = policy_merge(merged, filters, count, IN6_IS_ADDR_V4MAPPED(address));
	if(r < 0)
	{
		free(u);
		free(merged);
		return r;
	}
	if(u->existing)
	{
		/* rewrite the rules of the existing mapping */
		r = 0;
		if(merged->count != u->old.count ||
		   memcmp(merged->filters, u->old.filters,
		          merged->count * sizeof(merged->filters[0])) != 0)
			r = group_apply(merged, &u->old, &tpl);
		free(merged);
		if(r < 0)
		{
			free(u);
			return -1;
		}
	}
	else
	{
		/* the rules will be created with the mapping */
		free(pending_policy);
		pending_policy = merged;
	}
	*update = u;
	return 0;
}

int
pf_pcp_filter_finish(struct pcp_filter_update * update, int commit)
{
	int r = 0;
	if(update == NULL)
		return 0;
	free(pending_policy);
	pending_policy = NULL;
#ifdef ENABLE_UPNPPINHOLE
	if(update->existing && !commit && update->v6)
	{
		struct pf_pcp_policy cur;
		char desc[PF_RULE_LABEL_SIZE], ifn[IFNAMSIZ];
		unsigned int ts = 0;
		memset(&cur, 0, sizeof(cur));
		cur.address = update->old.address;
		cur.port = update->old.port;
		cur.protocol = update->old.protocol;
		if(pf_pinhole_group_get(&cur.address, cur.port, cur.protocol, cur.filters,
		                        PCP_FILTER_PEER_MAX, &cur.count,
		                        desc, sizeof(desc), &ts, ifn) > 0)
			r = group_apply6(&update->old, &cur, ifn, desc, ts);
	}
	else
#endif
	if(update->existing && !commit)
	{
		struct pf_pcp_policy cur;
		struct pf_group_template tpl;
		/* restore the previous policy */
		if(read_group(&update->old.address, update->old.port,
		              update->old.protocol, &cur, &tpl) > 0)
			r = group_apply(&update->old, &cur, &tpl);
	}
	free(update);
	return r;
}

int
pf_pcp_filter_delete(const struct in6_addr * address, unsigned short port,
                     unsigned char protocol)
{
	/* the policy is stored in the rules of the mapping */
	UNUSED(address); UNUSED(port); UNUSED(protocol);
	return 0;
}

#endif /* USE_PF */
