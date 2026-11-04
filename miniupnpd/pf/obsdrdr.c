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
#include "../peer_lease.h"

/* the structure returned by DIOCGETSTATES : renamed in FreeBSD 14 */
#if defined(__FreeBSD__) && __FreeBSD_version >= 1400000
#define PF_STATE_STRUCT struct pfsync_state_1301
#else
#define PF_STATE_STRUCT struct pfsync_state
#endif
#include "obsdrdr.h"
#include "../upnpglobalvars.h"
#include "../getifaddr.h"
#include "rtickets.h"
#include "../pcp_filter.h"
#include "pfpcp.h"
#include "pfrules.h"

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

/* shutdown_redirect() :
 * close the /dev/pf device */
void
shutdown_redirect(void)
{
	if(close(dev)<0)
		syslog(LOG_ERR, "close(\"/dev/pf\"): %m");
	dev = -1;
#ifdef PCP_PEER
	peer_lease_free_all();
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
			r = pf_rule_remove(NAT_RULE_ACTION, i) < 0 ? -1 : 0;
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
 * Rules are told apart from port triggering rules by their remote port.
 *
 * FreeBSD 15.1 : a NAT rule matched in an anchor does not end the evaluation
 * (pf_match_translation_rule(), fixed by b5219c068f in stable/15), so a later
 * rule of the main ruleset such as "nat on ext_if from lan -> (ext_if)"
 * overrides it and the flow leaves from a random port, not eport. Keep such a
 * rule from matching : set tag in miniupnpd.conf and add "! tagged <tag>" to
 * it. */
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
#define PEER_FIND	2
#define PEER_EACH	3

struct peer_walk_ctx {
	int op;
	int index;		/* PEER_GET : wanted rank among the PEER rules */
	int count;
	struct peer_nat * pn;	/* PEER_GET : result. PEER_DELETE/PEER_FIND : the key */
	int rule_index;		/* PEER_DELETE/PEER_FIND : position of the rule found */
	pcp_lease_peer_cb each;	/* PEER_EACH : called for each PEER rule */
	void * each_arg;
};

static int
peer_nat_cb(int i, const pf_walk_rule_t * rule,
            const struct pf_walk * walk, void * arg)
{
	struct peer_walk_ctx * c = arg;
	struct peer_nat * pn = c->pn;
#undef RULE
#define RULE (*rule)
	UNUSED(walk);
	if(RULE_DPORT_OP(RULE) != PF_OP_EQ || RULE.af != AF_INET)
		return 0;	/* not a PEER rule */
	if(c->op == PEER_GET && c->count++ != c->index)
		return 0;
	if(c->op == PEER_EACH)
	{
		struct pcp_lease_peer p;
		in_addr_t ia = RULE_V4(RULE.src.addr), ra = RULE_V4(RULE.dst.addr);
		memset(&p, 0, sizeof(p));
		inet_ntop(AF_INET, &ia, p.iaddr, sizeof(p.iaddr));
		inet_ntop(AF_INET, &ra, p.raddr, sizeof(p.raddr));
		p.iport = ntohs(RULE_SPORT(RULE));
		p.rport = ntohs(RULE_DPORT(RULE));
		p.eport = NAT_RULE_EPORT(RULE);
		p.proto = RULE.proto;
		strlcpy(p.desc, PF_RULE_LABEL_OF(RULE), sizeof(p.desc));
		strlcpy(p.ifname, RULE.ifname, sizeof(p.ifname));
		p.timestamp = peer_lease_get(ia, p.iport, ra, p.rport, p.proto);
		c->each(&p, c->each_arg);
		return 0;
	}
	if(c->op != PEER_GET)
	{
		if(!(pn->iport == ntohs(RULE_SPORT(RULE))
		  && pn->rport == ntohs(RULE_DPORT(RULE))
		  && RULE.proto == pn->proto
		  && pn->iaddr == RULE_V4(RULE.src.addr)
		  && pn->raddr == RULE_V4(RULE.dst.addr)))
			return 0;
		c->rule_index = i;
		if(c->op == PEER_DELETE)
			return 1;
	}
	pn->iaddr = RULE_V4(RULE.src.addr);
	pn->raddr = RULE_V4(RULE.dst.addr);
	pn->iport = ntohs(RULE_SPORT(RULE));
	pn->rport = ntohs(RULE_DPORT(RULE));
	pn->eport = NAT_RULE_EPORT(RULE);
	pn->proto = RULE.proto;
	strlcpy(pn->desc, PF_RULE_LABEL_OF(RULE), sizeof(pn->desc));
	strlcpy(pn->ifname, RULE.ifname, sizeof(pn->ifname));
#ifdef PFRULE_INOUT_COUNTS
	pn->packets = RULE.packets[0] + RULE.packets[1];
	pn->bytes = RULE.bytes[0] + RULE.bytes[1];
#else
	pn->packets = RULE.packets;
	pn->bytes = RULE.bytes;
#endif
	return 1;
#undef RULE
}

/* one pass over the NAT rules of the anchor :
 * PEER_GET : fill *pn with the index-th PEER rule
 * PEER_FIND : fill *pn with the rule matching iaddr/iport/raddr/rport/proto of *pn
 * PEER_DELETE : delete the rule matching iaddr/iport/raddr/rport/proto of *pn
 * returns:  0 : OK
 *          -1 : Error
 *          -2 : rule not found */
static int
peer_nat_walk(int op, int index, struct peer_nat * pn)
{
	struct peer_walk_ctx c;
	int r;
	c.op = op;
	c.index = index;
	c.count = 0;
	c.pn = pn;
	c.rule_index = -1;
	c.each = NULL;
	c.each_arg = NULL;
	r = pf_rule_foreach(NAT_RULE_ACTION, peer_nat_cb, &c);
	if(r < 0)
		return -1;
	if(r == 0)
		return -2;
	if(op == PEER_DELETE)
		return pf_rule_remove(NAT_RULE_ACTION, c.rule_index) < 0 ? -1 : 0;
	return 0;
}

/* find the PEER rule with this key; returns 0 if found */
static int
find_peer_nat(in_addr_t iaddr, unsigned short iport,
              in_addr_t raddr, unsigned short rport, int proto,
              struct peer_nat * pn)
{
	memset(pn, 0, sizeof(*pn));
	pn->iaddr = iaddr;
	pn->iport = iport;
	pn->raddr = raddr;
	pn->rport = rport;
	pn->proto = proto;
	return peer_nat_walk(PEER_FIND, 0, pn) == 0 ? 0 : -1;
}

/* a PEER mapping by its two endpoints, in one pass. returns 0 if found */
int
pf_pcp_find_peer(const char * iaddr, unsigned short iport,
                 const char * raddr, unsigned short rport, int proto,
                 unsigned short * eport, char * desc, int desclen,
                 unsigned int * timestamp)
{
	struct peer_nat pn;
	in_addr_t ia, ra;
	if(inet_pton(AF_INET, iaddr, &ia) != 1 || inet_pton(AF_INET, raddr, &ra) != 1)
		return -1;
	if(find_peer_nat(ia, iport, ra, rport, proto, &pn) != 0)
		return -1;
	*eport = pn.eport;
	if(desc != NULL && desclen > 0)
		strlcpy(desc, pn.desc, desclen);
	if(timestamp != NULL)
		*timestamp = peer_lease_get(ia, iport, ra, rport, proto);
	return 0;
}

int
delete_peer_rule(const char * iaddr, unsigned short iport,
                 const char * raddr, unsigned short rport, int proto)
{
	struct peer_nat pn;
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
	peer_lease_remove(pn.iaddr, iport, pn.raddr, rport, proto);
	return 0;
}

/* call cb for each PEER rule, in one pass (for pcp_lease.c) */
int
pf_pcp_lease_peers(pcp_lease_peer_cb cb, void * arg)
{
	struct peer_walk_ctx c;
	memset(&c, 0, sizeof(c));
	c.op = PEER_EACH;
	c.rule_index = -1;
	c.each = cb;
	c.each_arg = arg;
	return pf_rule_foreach(NAT_RULE_ACTION, peer_nat_cb, &c) < 0 ? -1 : 0;
}

#define PEER_EXPIRE_MAX_PER_PASS	64

unsigned int
expire_peer_rules(unsigned int now)
{
	/* each delete walks the rules : the next pass goes on */
	return peer_lease_expire(now, delete_peer_rule, PEER_EXPIRE_MAX_PER_PASS);
}

int
add_peer_redirect_rule2(const char * ifname,
                        const char * rhost, unsigned short rport,
                        const char * eaddr, unsigned short eport,
                        const char * iaddr, unsigned short iport, int proto,
                        const char * desc, unsigned int timestamp)
{
	struct peer_nat pn;
	in_addr_t ia, ra;
	unsigned int old_timestamp;
	int had_lease, r;

	if(inet_pton(AF_INET, iaddr, &ia) != 1 || inet_pton(AF_INET, rhost, &ra) != 1)
		return -1;
	had_lease = peer_lease_exists(ia, iport, ra, rport, proto);
	old_timestamp = peer_lease_get(ia, iport, ra, rport, proto);
	if(peer_lease_set(ia, iport, ra, rport, proto, timestamp) < 0)
		return -1;
	if(find_peer_nat(ia, iport, ra, rport, proto, &pn) == 0) {
		if(pn.eport == eport && strcmp(pn.desc, desc) == 0) {
			/* renewal : keep the rule, and its states */
			return 0;
		}
		/* different external port or description : replace the rule,
		 * the lease we found (if any) is kept */
		syslog(LOG_INFO, "Replace peer map %s:%hu/%s remote %s port %hu ext port %hu -> %hu via PCP",
		       iaddr, iport, proto == IPPROTO_TCP ? "TCP" : "UDP", rhost, rport,
		       pn.eport, eport);
		if(peer_nat_walk(PEER_DELETE, 0, &pn) == -1)
			r = -1;
		else
			r = add_nat_rule_full(ifname, rhost, rport, eaddr, eport,
			                      iaddr, iport, proto, desc);
	} else {
		r = add_nat_rule_full(ifname, rhost, rport, eaddr, eport,
		                      iaddr, iport, proto, desc);
	}
	if(r < 0) {
		/* back to the lease we had */
		if(had_lease)
			peer_lease_set(ia, iport, ra, rport, proto, old_timestamp);
		else
			peer_lease_remove(ia, iport, ra, rport, proto);
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
	if(timestamp)
		*timestamp = peer_lease_get(pn.iaddr, pn.iport, pn.raddr, pn.rport, pn.proto);
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
                 struct sockaddr * ret_ext)
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
		PF_STATE_STRUCT * st;
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
			len = ps.ps_len + 16 * sizeof(PF_STATE_STRUCT);
			free(buf);
			buf = malloc(len);
			if(buf == NULL)
				return -1;
			ps.ps_len = len;
			ps.ps_buf = buf;
		}
		n = ps.ps_len / sizeof(PF_STATE_STRUCT);
		st = (PF_STATE_STRUCT *)ps.ps_buf;
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
in_addr_t
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
int
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

static int remove_rdr_rules(unsigned short eport, int proto, int max);

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
	count = pf_pcp_pending_filters4(iaddr, iport, proto, &filters);
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
		if(r != 0)
		{
			/* do not keep a part of the rules of the mapping */
			if(k > 1)
				remove_rdr_rules(eport, proto, (int)k - 1);
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
int
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
	count = pf_pcp_pending_filters4(iaddr, iport, proto, &filters);
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
	if(r != 0)
	{
		/* do not keep a part of the rules of the mapping */
		struct in_addr ia;
		inet_pton(AF_INET, iaddr, &ia);
		while(k-- > 1)
		{
			memcpy(&ra.s_addr, filters[k - 1].address.s6_addr + 12, 4);
			filter_src_match.active = 1;
			filter_src_match.addr = ra.s_addr;
			filter_src_match.prefix = filters[k - 1].prefix - 96;
			filter_src_match.port = filters[k - 1].port;
			priv_delete_filter_rule(ifname, iport, proto, ia.s_addr);
			filter_src_match.active = 0;
		}
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
	pr.rule.action = PF_RDR;
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

/* the fields of a rdr rule which are returned by get_redirect_rule() and
 * get_redirect_rule_by_index().
 * returns 0 or -1 if the address of the redirection cannot be read */
static int
rdr_rule_info(int index, const pf_walk_rule_t * rule, const struct pf_walk * walk,
              unsigned short * iport, char * iaddr, int iaddrlen,
              char * desc, int desclen, char * rhost, int rhostlen,
              u_int64_t * packets, u_int64_t * bytes)
{
#ifndef PF_NEWSTYLE
	struct pfioc_pooladdr pp;
#else
	UNUSED(index); UNUSED(walk);
#endif
#ifndef PF_NEWSTYLE
	*iport = rule->rpool.proxy_port[0];
#else
	*iport = rule->rdr.proxy_port[0];
#endif
	if(desc)
		strlcpy(desc, PF_RULE_LABEL_OF(*rule), desclen);
#ifdef PFRULE_INOUT_COUNTS
	if(packets)
		*packets = rule->packets[0] + rule->packets[1];
	if(bytes)
		*bytes = rule->bytes[0] + rule->bytes[1];
#else
	if(packets)
		*packets = rule->packets;
	if(bytes)
		*bytes = rule->bytes;
#endif
#ifndef PF_NEWSTYLE
	memset(&pp, 0, sizeof(pp));
	strlcpy(pp.anchor, anchor_name, MAXPATHLEN);
	pp.r_action = walk->action;
	pp.r_num = index;
	pp.ticket = walk->ticket;
	if(ioctl(dev, DIOCGETADDRS, &pp) < 0)
	{
		syslog(LOG_ERR, "ioctl(dev, DIOCGETADDRS, ...): %m");
		return -1;
	}
	if(pp.nr != 1)
	{
		syslog(LOG_NOTICE, "No address associated with pf rule");
		return -1;
	}
	pp.nr = 0;	/* first */
	if(ioctl(dev, DIOCGETADDR, &pp) < 0)
	{
		syslog(LOG_ERR, "ioctl(dev, DIOCGETADDR, ...): %m");
		return -1;
	}
#ifdef PFVAR_NEW_STYLE
	inet_ntop(AF_INET, &pp.addr.addr.v.a.addr.v4addr.s_addr,
	          iaddr, iaddrlen);
#else
	inet_ntop(AF_INET, &pp.addr.addr.v.a.addr.v4.s_addr,
	          iaddr, iaddrlen);
#endif
#else
	inet_ntop(AF_INET, &rule->rdr.addr.v.a.addr.v4.s_addr,
	          iaddr, iaddrlen);
#endif
	if(rhost && rhostlen > 0)
	{
#ifdef PFVAR_NEW_STYLE
		if (rule->src.addr.v.a.addr.v4addr.s_addr == 0)
#else
		if (rule->src.addr.v.a.addr.v4.s_addr == 0)
#endif
		{
			rhost[0] = '\0'; /* empty string */
		}
		else
		{
#ifdef PFVAR_NEW_STYLE
			inet_ntop(AF_INET, &rule->src.addr.v.a.addr.v4addr.s_addr,
			          rhost, rhostlen);
#else
			inet_ntop(AF_INET, &rule->src.addr.v.a.addr.v4.s_addr,
			          rhost, rhostlen);
#endif
		}
	}
	return 0;
}

struct get_rdr_ctx {
	unsigned short eport;
	int proto;
	char * iaddr;
	int iaddrlen;
	unsigned short * iport;
	char * desc;
	int desclen;
	char * rhost;
	int rhostlen;
	unsigned int * timestamp;
	u_int64_t * packets;
	u_int64_t * bytes;
	int r;
};

static int
get_redirect_rule_cb(int index, const pf_walk_rule_t * rule,
                     const struct pf_walk * walk, void * arg)
{
	struct get_rdr_ctx * c = arg;
#ifdef __APPLE__
	if( (c->eport == ntohs(rule->dst.xport.range.port[0]))
	  && (c->eport == ntohs(rule->dst.xport.range.port[1]))
#else
	if( (c->eport == ntohs(rule->dst.port[0]))
	  && (c->eport == ntohs(rule->dst.port[1]))
#endif
	  && (rule->proto == c->proto) )
	{
		c->r = rdr_rule_info(index, rule, walk, c->iport, c->iaddr, c->iaddrlen,
		                     c->desc, c->desclen, c->rhost, c->rhostlen,
		                     c->packets, c->bytes);
		if(c->r == 0 && c->timestamp)
			*c->timestamp = get_timestamp(c->eport, c->proto);
		return 1;
	}
	return 0;
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
	struct get_rdr_ctx c;
	UNUSED(ifname);

	if(dev<0) {
		syslog(LOG_ERR, "pf device is not open");
		return -1;
	}
	c.eport = eport;
	c.proto = proto;
	c.iaddr = iaddr;
	c.iaddrlen = iaddrlen;
	c.iport = iport;
	c.desc = desc;
	c.desclen = desclen;
	c.rhost = rhost;
	c.rhostlen = rhostlen;
	c.timestamp = timestamp;
	c.packets = packets;
	c.bytes = bytes;
	c.r = -2;
	if(pf_rule_foreach(PF_RDR, get_redirect_rule_cb, &c) < 0)
		return -1;
	return c.r;
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
			if(pf_rule_remove(PF_RDR, i) < 0)
			{
				r = -1;
				break;
			}
			remove_timestamp_entry(eport, proto);
			r = 0;
			break;
		}
	}
	if (r == -2)
		syslog(LOG_NOTICE, "could not find redirect rule to delete eport=%hu", eport);
	release_ticket(dev, tnum);
	return r;
}

/* The indices of the rules a walk found, to remove them afterwards from the
 * last one : removing a rule moves the rules after it, not those before. */
struct rule_index_list {
	int * idx;
	int n, cap;
	int max;		/* at most this many, < 0 : no limit */
	unsigned short port;	/* rdr : eport, pass : iport */
	int proto;
	in_addr_t iaddr;	/* pass : 0 for any */
};

static int
rule_index_add(struct rule_index_list * l, int index)
{
	if(l->n == l->cap)
	{
		int cap = l->cap ? l->cap * 2 : 16;
		int * p = realloc(l->idx, cap * sizeof(*p));
		if(p == NULL)
			return -1;
		l->idx = p;
		l->cap = cap;
	}
	l->idx[l->n++] = index;
	return (l->max >= 0 && l->n >= l->max) ? 1 : 0;	/* 1 : stop the walk */
}

/* remove the rules of the list, from the last one. returns the number removed,
 * -1 on error */
static int
rule_index_remove(int action, struct rule_index_list * l, int walk_result)
{
	int i, removed = 0;
	if(walk_result < 0 || (l->n > 0 && l->idx == NULL))
	{
		free(l->idx);
		return -1;
	}
	for(i = l->n; i-- > 0; )
	{
		if(pf_rule_remove(action, l->idx[i]) < 0)
		{
			free(l->idx);
			return -1;
		}
		removed++;
	}
	free(l->idx);
	return removed;
}

static int
rdr_index_cb(int index, const pf_walk_rule_t * rule,
             const struct pf_walk * walk, void * arg)
{
	struct rule_index_list * l = arg;
	UNUSED(walk);
#ifdef __APPLE__
	if(l->port != ntohs(rule->dst.xport.range.port[0]) ||
	   l->port != ntohs(rule->dst.xport.range.port[1]))
#else
	if(l->port != ntohs(rule->dst.port[0]) ||
	   l->port != ntohs(rule->dst.port[1]))
#endif
		return 0;
	if(rule->proto != l->proto)
		return 0;
	return rule_index_add(l, index) != 0;	/* also stop when out of memory */
}

/* remove at most max (< 0 : all) rdr rules of eport/proto in one walk : the
 * other rules of a mapping which has several (PCP FILTER).
 * returns the number removed, -1 on error */
static int
remove_rdr_rules(unsigned short eport, int proto, int max)
{
	struct rule_index_list l;
	memset(&l, 0, sizeof(l));
	l.max = max;
	l.port = eport;
	l.proto = proto;
	if(max == 0)
		return 0;
	return rule_index_remove(PF_RDR, &l, pf_rule_foreach(PF_RDR, rdr_index_cb, &l));
}

#ifdef PF_ENABLE_FILTER_RULES
static int
pass_index_cb(int index, const pf_walk_rule_t * rule,
              const struct pf_walk * walk, void * arg)
{
	struct rule_index_list * l = arg;
	UNUSED(walk);
	if(l->port != ntohs(rule->dst.port[0]) || rule->proto != l->proto ||
	   (l->iaddr != 0 && l->iaddr != rule->dst.addr.v.a.addr.v4.s_addr))
		return 0;
	return rule_index_add(l, index) != 0;
}

/* remove the first max pass rules of iport/proto/iaddr in one walk.
 * returns the number removed, -1 on error */
static int
remove_pass_rules(unsigned short iport, int proto, in_addr_t iaddr, int max)
{
	struct rule_index_list l;
	memset(&l, 0, sizeof(l));
	l.max = max;
	l.port = iport;
	l.proto = proto;
	l.iaddr = iaddr;
	if(max == 0)
		return 0;
	return rule_index_remove(PF_PASS, &l, pf_rule_foreach(PF_PASS, pass_index_cb, &l));
}
#endif /* PF_ENABLE_FILTER_RULES */

int
delete_redirect_rule(const char * ifname, unsigned short eport,
                    int proto)
{
	int r;
	r = priv_delete_redirect_rule(ifname, eport, proto, NULL, NULL, NULL, 0);
	/* a filtered PCP mapping has a rule per allowed peer */
	if(r == 0 && remove_rdr_rules(eport, proto, -1) < 0)
		r = -1;
	return r;
}

/* when active, priv_delete_filter_rule() only removes the rule having this
 * source (used for the rules of a PCP FILTER policy) */
struct pf_filter_src_match filter_src_match;

/* returns:  0 : OK
 *          -1 : Error
 *          -2 : rule not found */
int
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
			r = pf_rule_remove(PF_PASS, i) < 0 ? -1 : 0;
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
	int r, others;
	unsigned short iport;
	in_addr_t iaddr;
	r = priv_delete_redirect_rule(ifname, eport, proto, &iport, &iaddr, NULL, 0);
	if(r == 0)
	{
		/* a filtered PCP mapping has a rule per allowed peer, and a pass
		 * rule for each : one walk each, not one per rule */
		others = remove_rdr_rules(eport, proto, -1);
#ifdef ENABLE_PORT_TRIGGERING
		if (proto == IPPROTO_UDP) {
			delete_nat_rule(ifname, eport, iport, proto, iaddr);
		}
#endif
		r = priv_delete_filter_rule(ifname, iport, proto, iaddr);
#ifdef PF_ENABLE_FILTER_RULES
		if(others > 0)
			remove_pass_rules(iport, proto, iaddr, others);
#endif
		if(others < 0)
			r = -1;
	}
	return r;
}

/* source restriction of the rule returned by the last successful call
 * to get_redirect_rule_by_index() */
in_addr_t last_rdr_src_addr;
unsigned int last_rdr_src_prefix;
unsigned short last_rdr_src_port;

/* source restriction of a rdr rule : address (network byte order), prefix
 * length (0 : any address) and port (0 : any port) */
static void
rdr_src_restriction(const pf_walk_rule_t * rule, in_addr_t * addr,
                    unsigned int * prefix, unsigned short * port)
{
	in_addr_t m;
#ifdef PFVAR_NEW_STYLE
	m = rule->src.addr.v.a.mask.v4addr.s_addr;
	*addr = rule->src.addr.v.a.addr.v4addr.s_addr;
#else
	m = rule->src.addr.v.a.mask.v4.s_addr;
	*addr = rule->src.addr.v.a.addr.v4.s_addr;
#endif
	*prefix = 0;
	m = ntohl(m);
	while(m & 0x80000000U) { (*prefix)++; m <<= 1; }
	if(*addr == 0)
		*prefix = 0;
#ifdef __APPLE__
	*port = rule->src.xport.range.op == PF_OP_EQ ?
	        ntohs(rule->src.xport.range.port[0]) : 0;
#else
	*port = rule->src.port_op == PF_OP_EQ ? ntohs(rule->src.port[0]) : 0;
#endif
}

struct rdr_index_ctx {
	char * ifname;
	unsigned short * eport;
	char * iaddr;
	int iaddrlen;
	unsigned short * iport;
	int * proto;
	char * desc;
	int desclen;
	char * rhost;
	int rhostlen;
	unsigned int * timestamp;
	u_int64_t * packets;
	u_int64_t * bytes;
};

static int
get_redirect_rule_by_index_cb(int index, const pf_walk_rule_t * rule,
                              const struct pf_walk * walk, void * arg)
{
	struct rdr_index_ctx * c = arg;
	*c->proto = rule->proto;
#ifdef __APPLE__
	*c->eport = ntohs(rule->dst.xport.range.port[0]);
#else
	*c->eport = ntohs(rule->dst.port[0]);
#endif
	if(c->ifname)
		strlcpy(c->ifname, rule->ifname, IFNAMSIZ);
	if(rdr_rule_info(index, rule, walk, c->iport, c->iaddr, c->iaddrlen,
	                 c->desc, c->desclen, c->rhost, c->rhostlen,
	                 c->packets, c->bytes) < 0)
		return -1;
	if(c->timestamp)
		*c->timestamp = get_timestamp(*c->eport, *c->proto);
	/* source restriction of the rule, used by the PCP FILTER code */
	rdr_src_restriction(rule, &last_rdr_src_addr, &last_rdr_src_prefix,
	                    &last_rdr_src_port);
	return 0;
}

int
get_redirect_rule_by_index(int index,
                           char * ifname, unsigned short * eport,
                           char * iaddr, int iaddrlen, unsigned short * iport,
                           int * proto, char * desc, int desclen,
                           char * rhost, int rhostlen,
                           unsigned int * timestamp,
                           u_int64_t * packets, u_int64_t * bytes)
{
	struct rdr_index_ctx c;
	if(index < 0)
		return -1;
	if(dev<0) {
		syslog(LOG_ERR, "pf device is not open");
		return -1;
	}
	c.ifname = ifname;
	c.eport = eport;
	c.iaddr = iaddr;
	c.iaddrlen = iaddrlen;
	c.iport = iport;
	c.proto = proto;
	c.desc = desc;
	c.desclen = desclen;
	c.rhost = rhost;
	c.rhostlen = rhostlen;
	c.timestamp = timestamp;
	c.packets = packets;
	c.bytes = bytes;
	return pf_rule_get(PF_RDR, index, get_redirect_rule_by_index_cb, &c) == 0 ? 0 : -1;
}

struct rdr_foreach_ctx {
	pf_rdr_visit_cb visit;
	void * arg;
};

static int
rdr_foreach_cb(int index, const pf_walk_rule_t * rule,
               const struct pf_walk * walk, void * arg)
{
	struct rdr_foreach_ctx * c = arg;
	char iaddr[INET_ADDRSTRLEN], desc[PF_RULE_LABEL_SIZE];
	unsigned short iport, eport, sport;
	unsigned int prefix;
	in_addr_t saddr;
	if(rdr_rule_info(index, rule, walk, &iport, iaddr, sizeof(iaddr),
	                 desc, sizeof(desc), NULL, 0, NULL, NULL) < 0)
		return 0;	/* skip the rules we cannot read */
#ifdef __APPLE__
	eport = ntohs(rule->dst.xport.range.port[0]);
#else
	eport = ntohs(rule->dst.port[0]);
#endif
	rdr_src_restriction(rule, &saddr, &prefix, &sport);
	return c->visit(index, rule->ifname, eport, iaddr, iport, rule->proto,
	                desc, saddr, prefix, sport,
	                get_timestamp(eport, rule->proto), c->arg);
}

/* see pfpcp.h */
int
get_redirect_rules_foreach(pf_rdr_visit_cb visit, void * arg)
{
	struct rdr_foreach_ctx c;
	c.visit = visit;
	c.arg = arg;
	return pf_rule_foreach(PF_RDR, rdr_foreach_cb, &c);
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


#endif /* USE_PF */
