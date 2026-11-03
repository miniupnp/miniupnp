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
#include "pfrules.h"

/* the pass rules created by add_pinhole() are as follow :
 *
 * pass in quick on ep0 inet6 proto udp
 *   from any to dead:beef::42:42 port = 8080
 *   flags S/SA keep state
 *   label "pinhole-2 ts-4321000"
 *
 * with the label "pinhole-$uid ts-$timestamp: $description"
 */

#ifdef ENABLE_UPNPPINHOLE

/* /dev/pf when opened */
extern int dev;

static int next_uid = 1;

#define PINEHOLE_LABEL_FORMAT "pinhole-%d ts-%u: %s"
#define PINEHOLE_LABEL_FORMAT_SKIPDESC "pinhole-%d ts-%u: %*s"

#define RULE (pr.rule)

int add_pinhole(const char * ifname,
                const char * rem_host, unsigned short rem_port,
                const char * int_client, unsigned short int_port,
                int proto, const char * desc, unsigned int timestamp)
{
	int uid;
	struct pfioc_rule pr;
#ifndef PF_NEWSTYLE
	struct pfioc_pooladdr pp;
#endif

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
		uid = next_uid;
		snprintf(RULE.label, PF_RULE_LABEL_SIZE,
		         PINEHOLE_LABEL_FORMAT, uid, timestamp, desc);
		if(queue)
			strlcpy(RULE.qname, queue, PF_QNAME_SIZE);
		if(tag)
			strlcpy(RULE.tagname, tag, PF_TAG_NAME_SIZE);

		if(rem_port) {
			RULE.src.port_op = PF_OP_EQ;
			RULE.src.port[0] = htons(rem_port);
		}
		if(rem_host && rem_host[0] != '\0' && rem_host[0] != '*') {
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

	if(++next_uid >= 65535) {
		next_uid = 1;
	}
	return uid;
}

/* the pinhole rules are all PF_PASS rules of the anchor */

struct find_ctx {
	int proto;
	unsigned short rem_port;
	unsigned short int_port;
	struct in6_addr saddr;
	struct in6_addr daddr;
	char * desc;
	int desc_len;
	unsigned int * timestamp;
	int uid;
};

static int
find_pinhole_cb(int index, const pf_walk_rule_t * rule,
                const struct pf_walk * walk, void * ctx)
{
	struct find_ctx * c = ctx;
	int uid;
	unsigned int ts;
	const char * label = PF_RULE_LABEL_OF(*rule);
	UNUSED(index); UNUSED(walk);

	if((c->proto == rule->proto) && (c->rem_port == ntohs(rule->src.port[0]))
	   && (0 == memcmp(&c->saddr, &rule->src.addr.v.a.addr.v6, sizeof(struct in6_addr)))
	   && (c->int_port == ntohs(rule->dst.port[0])) &&
	   (0 == memcmp(&c->daddr, &rule->dst.addr.v.a.addr.v6, sizeof(struct in6_addr)))) {
		if(sscanf(label, PINEHOLE_LABEL_FORMAT_SKIPDESC, &uid, &ts) != 2) {
			syslog(LOG_DEBUG, "rule with label '%s' is not a IGD pinhole", label);
			return 0;
		}
		if(c->timestamp) *c->timestamp = ts;
		if(c->desc) {
			const char * p = strchr(label, ':');
			if(p) {
				p += 2;
				strlcpy(c->desc, p, c->desc_len);
			}
		}
		c->uid = uid;
		return 1;
	}
	return 0;
}

int find_pinhole(const char * ifname,
                 const char * rem_host, unsigned short rem_port,
                 const char * int_client, unsigned short int_port,
                 int proto,
                 char *desc, int desc_len, unsigned int * timestamp)
{
	struct find_ctx c;
	int r;
	UNUSED(ifname);

	if(dev<0) {
		syslog(LOG_ERR, "pf device is not open");
		return -1;
	}
	memset(&c, 0, sizeof(c));
	c.proto = proto;
	c.rem_port = rem_port;
	c.int_port = int_port;
	c.desc = desc;
	c.desc_len = desc_len;
	c.timestamp = timestamp;
	if(rem_host && (rem_host[0] != '\0')) {
		inet_pton(AF_INET6, rem_host, &c.saddr);
	}
	inet_pton(AF_INET6, int_client, &c.daddr);
	r = pf_rule_foreach(PF_PASS, find_pinhole_cb, &c);
	if(r < 0)
		return -1;
	return (r == 1) ? c.uid : -2;
}

/* the label of a pinhole rule starts with "pinhole-<uid>" */
static int
label_is_pinhole(const char * label, unsigned short uid)
{
	char label_start[PF_RULE_LABEL_SIZE];
	char tmp_label[PF_RULE_LABEL_SIZE];
	snprintf(label_start, sizeof(label_start), "pinhole-%hu", uid);
	strlcpy(tmp_label, label, sizeof(tmp_label));
	strtok(tmp_label, " ");
	return 0 == strcmp(tmp_label, label_start);
}

struct uid_ctx {
	unsigned short uid;
	int index;
};

static int
uid_index_cb(int index, const pf_walk_rule_t * rule,
             const struct pf_walk * walk, void * ctx)
{
	struct uid_ctx * c = ctx;
	UNUSED(walk);
	if(label_is_pinhole(PF_RULE_LABEL_OF(*rule), c->uid)) {
		c->index = index;
		return 1;
	}
	return 0;
}

int delete_pinhole(unsigned short uid)
{
	struct uid_ctx c;
	int r;

	if(dev<0) {
		syslog(LOG_ERR, "pf device is not open");
		return -1;
	}
	c.uid = uid;
	c.index = -1;
	r = pf_rule_foreach(PF_PASS, uid_index_cb, &c);
	if(r < 0)
		return -1;
	if(r == 0)
		return -2;	/* not found */
	return pf_rule_remove(PF_PASS, c.index);
}

struct info_ctx {
	unsigned short uid;
	char * rem_host;
	int rem_hostlen;
	unsigned short * rem_port;
	char * int_client;
	int int_clientlen;
	unsigned short * int_port;
	int * proto;
	char * desc;
	int desclen;
	unsigned int * timestamp;
	u_int64_t * packets;
	u_int64_t * bytes;
	int result;
};

static int
info_cb(int index, const pf_walk_rule_t * rule,
        const struct pf_walk * walk, void * ctx)
{
	struct info_ctx * c = ctx;
	char tmp_label[PF_RULE_LABEL_SIZE];
	char * p;
	UNUSED(index); UNUSED(walk);

	if(!label_is_pinhole(PF_RULE_LABEL_OF(*rule), c->uid))
		return 0;
	strlcpy(tmp_label, PF_RULE_LABEL_OF(*rule), sizeof(tmp_label));
	p = tmp_label;
	strsep(&p, " ");
	if(c->rem_host && (inet_ntop(AF_INET6, &rule->src.addr.v.a.addr.v6, c->rem_host, c->rem_hostlen) == NULL)) {
		c->result = -1;
		return 1;
	}
	if(c->rem_port)
		*c->rem_port = ntohs(rule->src.port[0]);
	if(c->int_client && (inet_ntop(AF_INET6, &rule->dst.addr.v.a.addr.v6, c->int_client, c->int_clientlen) == NULL)) {
		c->result = -1;
		return 1;
	}
	if(c->int_port)
		*c->int_port = ntohs(rule->dst.port[0]);
	if(c->proto)
		*c->proto = rule->proto;
	if(c->timestamp)
		sscanf(p, "ts-%u", c->timestamp);
	if(c->desc) {
		strsep(&p, " ");
		if(p) {
			strlcpy(c->desc, p, c->desclen);
		} else {
			c->desc[0] = '\0';
		}
	}
#ifdef PFRULE_INOUT_COUNTS
	if(c->packets)
		*c->packets = rule->packets[0] + rule->packets[1];
	if(c->bytes)
		*c->bytes = rule->bytes[0] + rule->bytes[1];
#else
	if(c->packets)
		*c->packets = rule->packets;
	if(c->bytes)
		*c->bytes = rule->bytes;
#endif
	c->result = 0;
	return 1;
}

int
get_pinhole_info(unsigned short uid,
                 char * rem_host, int rem_hostlen, unsigned short * rem_port,
                 char * int_client, int int_clientlen, unsigned short * int_port,
                 int * proto, char * desc, int desclen,
                 unsigned int * timestamp,
                 u_int64_t * packets, u_int64_t * bytes)
{
	struct info_ctx c;
	int r;

	if(dev<0) {
		syslog(LOG_ERR, "pf device is not open");
		return -1;
	}
	c.uid = uid;
	c.rem_host = rem_host; c.rem_hostlen = rem_hostlen; c.rem_port = rem_port;
	c.int_client = int_client; c.int_clientlen = int_clientlen; c.int_port = int_port;
	c.proto = proto; c.desc = desc; c.desclen = desclen; c.timestamp = timestamp;
	c.packets = packets; c.bytes = bytes;
	c.result = -2;	/* not found */
	r = pf_rule_foreach(PF_PASS, info_cb, &c);
	if(r < 0)
		return -1;
	return c.result;
}

int update_pinhole(unsigned short uid, unsigned int timestamp)
{
	/* TODO :
	 * As it is not possible to change rule label, we should :
	 * 1 - delete
	 * 2 - Add new
	 * the stats of the rule will then be reset :( */
	UNUSED(uid); UNUSED(timestamp);
	return -42; /* not implemented */
}

/* return the number of rules removed
 * or a negative integer in case of error */
int clean_pinhole_list(unsigned int * next_timestamp)
{
	int i;
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
	time_t current_time;
	unsigned int ts, tnum;
	int uid;
	unsigned int min_ts = UINT_MAX;
	int min_uid = INT_MAX, max_uid = -1;
	int n = 0;

	if(dev<0) {
		syslog(LOG_ERR, "pf device is not open");
		return -1;
	}
	current_time = upnp_time();
#ifdef USE_LIBPFCTL
	if(pfctl_get_rules_info(dev, &ri, PF_PASS, anchor_name) < 0)
	{
		syslog(LOG_ERR, "pfctl_get_rules_info: %m");
		return -1;
	}
	i = ri.nr - 1;
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
	i = pr.nr - 1;
#ifdef PF_RELEASETICKETS
	tnum = pr.ticket;
#endif
#endif /* USE_LIBPFCTL */
	for(; i >= 0; i--) {
#ifdef USE_LIBPFCTL
		if(pfctl_get_rule(dev, i, ri.ticket, anchor_name, PF_PASS, &rule, anchor_call) < 0)
		{
			syslog(LOG_ERR, "pfctl_get_rule: %m");
			release_ticket(dev, tnum);
			return -1;
		}
		if(sscanf(RULE.label[0], PINEHOLE_LABEL_FORMAT_SKIPDESC, &uid, &ts) != 2) {
			syslog(LOG_DEBUG, "rule with label '%s' is not a IGD pinhole", RULE.label[0]);
			continue;
		}
#else /* USE_LIBPFCTL */
		pr.nr = i;
		if(ioctl(dev, DIOCGETRULE, &pr) < 0) {
			syslog(LOG_ERR, "ioctl(dev, DIOCGETRULE): %m");
			release_ticket(dev, tnum);
			return -1;
		}
		if(sscanf(RULE.label, PINEHOLE_LABEL_FORMAT_SKIPDESC, &uid, &ts) != 2) {
			syslog(LOG_DEBUG, "rule with label '%s' is not a IGD pinhole", RULE.label);
			continue;
		}
#endif /* USE_LIBPFCTL */
		if(ts <= (unsigned int)current_time) {
#ifdef USE_LIBPFCTL
			/* TODO: convert DIOCCHANGERULE to libpfctl */
			struct pfioc_rule pr;
			pr.action = PF_CHANGE_GET_TICKET;
			memset(&pr, 0, sizeof(pr));
			pr.ticket = ri.ticket;
			pr.nr = i;
			strlcpy(pr.anchor, anchor_name, MAXPATHLEN);
			syslog(LOG_INFO, "removing expired pinhole '%s'", RULE.label[0]);
#else /* USE_LIBPFCTL */
			syslog(LOG_INFO, "removing expired pinhole '%s'", RULE.label);
#endif /* USE_LIBPFCTL */
			pr.action = PF_CHANGE_GET_TICKET;
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
			n++;
#ifdef USE_LIBPFCTL
			if(pfctl_get_rules_info(dev, &ri, PF_PASS, anchor_name) < 0)
			{
				syslog(LOG_ERR, "pfctl_get_rules_info: %m");
				return -1;
			}
#ifdef PF_RELEASETICKETS
			tnum = ri.ticket;
#endif /* PF_RELEASETICKETS */
#else /* USE_LIBPFCTL */
#ifndef PF_NEWSTYLE
			RULE.action = PF_PASS;
#endif
			release_ticket(dev, tnum);
			if(ioctl(dev, DIOCGETRULES, &pr) < 0) {
				syslog(LOG_ERR, "ioctl(dev, DIOCGETRULES, ...): %m");
				return -1;
			}
#ifdef PF_RELEASETICKETS
			tnum = pr.ticket;
#endif
#endif /* USE_LIBPFCTL */
		} else {
			if(uid > max_uid)
				max_uid = uid;
			else if(uid < min_uid)
				min_uid = uid;
			if(ts < min_ts)
				min_ts = ts;
		}
	}
	if(next_timestamp && (min_ts != UINT_MAX))
		*next_timestamp = min_ts;
	if(max_uid > 0) {
		if(((min_uid - 32000) <= next_uid) && (next_uid <= max_uid)) {
			next_uid = max_uid + 1;
		}
		if(next_uid >= 65535) {
			next_uid = 1;
		}
	}
	release_ticket(dev, tnum);
	return n;	/* number of rules removed */
}

#endif /* ENABLE_UPNPPINHOLE */
