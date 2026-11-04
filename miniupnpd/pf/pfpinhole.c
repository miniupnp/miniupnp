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
#include "../pcp_filter.h"

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

static int delete_pinhole_one(unsigned short uid);
static int pinhole_alloc_uid(void);
static void pinhole_uid_set(int uid);

/* uid_in : the uid to use, 0 to allocate a new one
 * prefix : length of the prefix of rem_host the source must match (1-128) */
static int add_pinhole_ex(int uid_in, const char * ifname,
                const char * rem_host, unsigned int prefix, unsigned short rem_port,
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
	/* a uid no live pinhole has : next_uid wraps at 65535, and a FILTER
	 * group takes a uid per peer */
	if(uid_in <= 0 && pinhole_alloc_uid() < 0) {
		syslog(LOG_ERR, "no free pinhole uid");
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
		uid = uid_in > 0 ? uid_in : next_uid;
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
			memset(&RULE.src.addr.v.a.mask.addr8, 0, 16);
			{
				unsigned int i;
				for(i = 0; i < 16 && prefix > 0; i++, prefix = prefix >= 8 ? prefix - 8 : 0)
					RULE.src.addr.v.a.mask.addr8[i] = prefix >= 8 ? 255 : (255 << (8 - prefix)) & 255;
			}
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

	pinhole_uid_set(uid);
	if(uid_in <= 0 && ++next_uid >= 65535) {
		next_uid = 1;
	}
	return uid;
}

#define RULE_LABEL(r)	PF_RULE_LABEL_OF(r)

/* pinholes created for a PCP MAP request have the description
 * "PCP MAP <nonce>".  The pinholes of one mapping which has a FILTER policy
 * (one pinhole per allowed remote peer) are managed as a group. */
static int
label_is_pcp_map(const char * label)
{
	const char * p = strchr(label, ':');
	return p != NULL && strncmp(p + 1, " PCP MAP ", 9) == 0;
}

struct pinhole_rec {
	int index;	/* position in the PASS rules during the walk */
	int uid;
	unsigned int ts;
	struct in6_addr src, dst;
	unsigned int prefix;
	unsigned short sport, dport;
	int proto;
	char desc[PF_RULE_LABEL_SIZE];
	char ifname[IFNAMSIZ];
};

/* called for each pinhole, return non zero to stop the walk.
 * It must not change the rules. */
typedef int (*pinhole_visit_cb)(const struct pinhole_rec * rec, void * ctx);

struct pinhole_walk_ctx {
	pinhole_visit_cb visit;
	void * arg;
};

static int
pinhole_walk_cb(int i, const pf_walk_rule_t * rule,
                const struct pf_walk * walk, void * arg)
{
	struct pinhole_walk_ctx * c = arg;
	struct pinhole_rec rec;
	unsigned int ts;
	int uid, k;
	const char * p;
	UNUSED(walk);
	if(rule->af != AF_INET6 ||
	   sscanf(RULE_LABEL(*rule), PINEHOLE_LABEL_FORMAT_SKIPDESC, &uid, &ts) != 2)
		return 0;
	rec.uid = uid;
	rec.ts = ts;
	rec.index = i;
	rec.src = rule->src.addr.v.a.addr.v6;
	rec.dst = rule->dst.addr.v.a.addr.v6;
	rec.prefix = 0;
	for(k = 0; k < 16; k++) {
		unsigned char m = rule->src.addr.v.a.mask.addr8[k];
		while(m & 0x80) { rec.prefix++; m <<= 1; }
	}
	rec.sport = rule->src.port_op == PF_OP_EQ ? ntohs(rule->src.port[0]) : 0;
	rec.dport = ntohs(rule->dst.port[0]);
	rec.proto = rule->proto;
	p = strchr(RULE_LABEL(*rule), ':');
	strlcpy(rec.desc, p ? p + 2 : "", sizeof(rec.desc));
	strlcpy(rec.ifname, rule->ifname, sizeof(rec.ifname));
	return c->visit(&rec, c->arg);
}

/* visit the pinholes in one pass over the ruleset.
 * returns 1 if stopped by visit(), 0 at the end of the list, -1 on error */
static int
pinhole_foreach(pinhole_visit_cb visit, void * arg)
{
	struct pinhole_walk_ctx c;
	c.visit = visit;
	c.arg = arg;
	return pf_rule_foreach(PF_PASS, pinhole_walk_cb, &c);
}

struct find_uid_ctx {
	int uid;
	struct pinhole_rec * rec;
};

static int
find_uid_cb(const struct pinhole_rec * rec, void * arg)
{
	struct find_uid_ctx * c = arg;
	if(rec->uid != c->uid)
		return 0;
	*c->rec = *rec;
	return 1;
}

/* The uids of the pinholes : a bit per uid, set when a pinhole is added. It
 * is built by a walk of the rules the first time (pinholes may be left from
 * an earlier run), and again when no free uid is found : a bit of a pinhole
 * which is gone only wastes its uid until then. */
static unsigned char uid_used[65536 / 8];
static int uid_map_valid = 0;

#define UID_BIT_SET(u)	(uid_used[(u) >> 3] & (1 << ((u) & 7)))

static void
pinhole_uid_set(int uid)
{
	if(uid > 0 && uid < 65536)
		uid_used[uid >> 3] |= (unsigned char)(1 << (uid & 7));
}

static int
uid_map_cb(const struct pinhole_rec * rec, void * arg)
{
	UNUSED(arg);
	pinhole_uid_set(rec->uid);
	return 0;
}

/* make next_uid a uid which no pinhole has. returns <0 if none */
static int
pinhole_alloc_uid(void)
{
	int pass, tries;
	for(pass = 0; pass < 2; pass++) {
		if(!uid_map_valid || pass == 1) {
			memset(uid_used, 0, sizeof(uid_used));
			if(pinhole_foreach(uid_map_cb, NULL) < 0)
				return -1;
			uid_map_valid = 1;
		}
		for(tries = 0; tries < 65534; tries++) {
			if(!UID_BIT_SET(next_uid))
				return next_uid;
			if(++next_uid >= 65535)
				next_uid = 1;
		}
	}
	return -1;
}

/* get the first rule of this uid. returns 0 if found */
static int
pinhole_find_uid(int uid, struct pinhole_rec * rec)
{
	struct find_uid_ctx c;
	c.uid = uid;
	c.rec = rec;
	return pinhole_foreach(find_uid_cb, &c) == 1 ? 0 : -1;
}

/* the pinholes of the group of a mapping (from a PCP MAP request) : those
 * with the destination, port, protocol and description of rec, up to
 * PCP_FILTER_PEER_MAX + 1 per walk */
struct members_ctx {
	const struct pinhole_rec * rec;	/* a member of the group */
	struct pinhole_rec * members;
	unsigned int n;
};

static int
members_cb(const struct pinhole_rec * rec, void * arg)
{
	struct members_ctx * c = arg;
	if(rec->dport == c->rec->dport && rec->proto == c->rec->proto &&
	   memcmp(&rec->dst, &c->rec->dst, sizeof(rec->dst)) == 0 &&
	   strcmp(rec->desc, c->rec->desc) == 0)
		c->members[c->n++] = *rec;
	return c->n == PCP_FILTER_PEER_MAX + 1;
}

int add_pinhole(const char * ifname,
                const char * rem_host, unsigned short rem_port,
                const char * int_client, unsigned short int_port,
                int proto, const char * desc, unsigned int timestamp)
{
	struct in6_addr d;
	const struct pcp_filter * f = NULL;
	unsigned int n, k;
	int uid, first = -1;
	int added[PCP_FILTER_PEER_MAX];
	if((rem_host == NULL || rem_host[0] == '\0' || rem_host[0] == '*') && rem_port == 0
	   && inet_pton(AF_INET6, int_client, &d) == 1
	   && (n = pf_pcp_pending_filters6(&d, int_port, proto, &f)) > 0) {
		/* PCP MAP with FILTER options : a pinhole per allowed peer */
		if(n > PCP_FILTER_PEER_MAX)
			return -1;
		for(k = 0; k < n; k++) {
			char host[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, &f[k].address, host, sizeof(host));
			uid = add_pinhole_ex(0, ifname, host, f[k].prefix, f[k].port,
			                     int_client, int_port, proto, desc, timestamp);
			if(uid < 0) {
				while(k-- > 0)
					delete_pinhole_one((unsigned short)added[k]);
				return -1;
			}
			added[k] = uid;
			if(first < 0)
				first = uid;
		}
		return first;
	}
	return add_pinhole_ex(0, ifname, rem_host, 128, rem_port,
	                      int_client, int_port, proto, desc, timestamp);
}

/* ---- groups of pinholes of PCP MAP mappings (FILTER) ---- */

struct group_get_ctx {
	const struct in6_addr * dst;
	unsigned short port;
	int proto;
	struct pcp_filter * filters;
	unsigned int max, * nfilters, count;
	char * desc;
	int desclen;
	unsigned int * timestamp;
	char * ifname;
};

static int
group_get_cb(const struct pinhole_rec * rec, void * arg)
{
	struct group_get_ctx * c = arg;
	if(rec->dport != c->port || rec->proto != c->proto ||
	   memcmp(&rec->dst, c->dst, sizeof(*c->dst)) != 0 ||
	   strncmp(rec->desc, "PCP MAP ", 8) != 0)
		return 0;
	if(c->count++ == 0) {
		if(c->desc) strlcpy(c->desc, rec->desc, c->desclen);
		if(c->timestamp) *c->timestamp = rec->ts;
		if(c->ifname) strlcpy(c->ifname, rec->ifname, IFNAMSIZ);
	}
	if(rec->prefix > 0 && *c->nfilters < c->max) {
		c->filters[*c->nfilters].address = rec->src;
		c->filters[*c->nfilters].prefix = rec->prefix;
		c->filters[*c->nfilters].port = rec->sport;
		(*c->nfilters)++;
	}
	return 0;
}

/* read the policy of a mapping. returns the number of pinholes */
unsigned int
pf_pinhole_group_get(const struct in6_addr * dst, unsigned short port, int proto,
                     struct pcp_filter * filters, unsigned int max,
                     unsigned int * nfilters, char * desc, int desclen,
                     unsigned int * timestamp, char * ifname)
{
	struct group_get_ctx c;
	*nfilters = 0;
	c.dst = dst;
	c.port = port;
	c.proto = proto;
	c.filters = filters;
	c.max = max;
	c.nfilters = nfilters;
	c.count = 0;
	c.desc = desc;
	c.desclen = desclen;
	c.timestamp = timestamp;
	c.ifname = ifname;
	pinhole_foreach(group_get_cb, &c);
	return c.count;
}

static int
group_index_cb(const struct pinhole_rec * rec, void * arg)
{
	struct pcp_filter f;
	UNUSED(arg);
	/* as group_get_cb() */
	if(strncmp(rec->desc, "PCP MAP ", 8) != 0 || rec->prefix == 0)
		return 0;
	memset(&f, 0, sizeof(f));
	f.address = rec->src;
	f.prefix = rec->prefix;
	f.port = rec->sport;
	pf_pcp_filter_index_add(&rec->dst, rec->dport, (unsigned char)rec->proto, &f);
	return 0;
}

/* add the peers of all the mappings to the index of a save.
 * returns <0 on error */
int
pf_pinhole_group_index(void)
{
	return pinhole_foreach(group_index_cb, NULL);
}

/* add a pinhole for a peer (NULL : any source) to a mapping */
int
pf_pinhole_group_add(const char * ifname, const struct in6_addr * dst,
                     unsigned short port, int proto, const char * desc,
                     unsigned int timestamp, const struct pcp_filter * f)
{
	char host[INET6_ADDRSTRLEN], client[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, dst, client, sizeof(client));
	if(f)
		inet_ntop(AF_INET6, &f->address, host, sizeof(host));
	return add_pinhole_ex(0, ifname, f ? host : NULL, f ? f->prefix : 0,
	                      f ? f->port : 0, client, port, proto, desc, timestamp);
}

struct group_remove_ctx {
	const struct in6_addr * dst;
	unsigned short port;
	int proto;
	const struct pcp_filter * f;
	int uid;
};

static int
group_remove_cb(const struct pinhole_rec * rec, void * arg)
{
	struct group_remove_ctx * c = arg;
	if(rec->dport != c->port || rec->proto != c->proto ||
	   memcmp(&rec->dst, c->dst, sizeof(*c->dst)) != 0 ||
	   strncmp(rec->desc, "PCP MAP ", 8) != 0)
		return 0;
	if(c->f == NULL ? rec->prefix == 0 :
	   (rec->prefix == c->f->prefix && rec->sport == c->f->port &&
	    memcmp(&rec->src, &c->f->address, sizeof(rec->src)) == 0)) {
		c->uid = rec->uid;
		return 1;
	}
	return 0;
}

/* remove the pinhole for a peer (NULL : any source) of a mapping */
int
pf_pinhole_group_remove(const struct in6_addr * dst, unsigned short port,
                        int proto, const struct pcp_filter * f)
{
	struct group_remove_ctx c;
	c.dst = dst;
	c.port = port;
	c.proto = proto;
	c.f = f;
	if(pinhole_foreach(group_remove_cb, &c) != 1)
		return -2;
	return delete_pinhole_one((unsigned short)c.uid);
}

int find_pinhole(const char * ifname,
                 const char * rem_host, unsigned short rem_port,
                 const char * int_client, unsigned short int_port,
                 int proto,
                 char *desc, int desc_len, unsigned int * timestamp)
{
	int uid;
	unsigned int ts, tnum;
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
	UNUSED(ifname);

	if(dev<0) {
		syslog(LOG_ERR, "pf device is not open");
		return -1;
	}
	if(rem_host && (rem_host[0] != '\0')) {
		inet_pton(AF_INET6, rem_host, &saddr);
	} else {
		memset(&saddr, 0, sizeof(struct in6_addr));
	}
	inet_pton(AF_INET6, int_client, &daddr);
#ifdef USE_LIBPFCTL
	if(pfctl_get_rules_info(dev, &ri, PF_PASS, anchor_name) < 0)
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
		if(pfctl_get_rule(dev, i, ri.ticket, anchor_name, PF_PASS, &rule, anchor_call) < 0)
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
		if((proto == RULE.proto)
		   && (((rem_port == ntohs(RULE.src.port[0]))
		        && (0 == memcmp(&saddr, &RULE.src.addr.v.a.addr.v6, sizeof(struct in6_addr))))
		       /* any source : also find the filtered pinholes of a PCP mapping */
		       || (rem_port == 0 && IN6_IS_ADDR_UNSPECIFIED(&saddr)
		           && label_is_pcp_map(RULE_LABEL(RULE))))
		   && (int_port == ntohs(RULE.dst.port[0])) &&
		   (0 == memcmp(&daddr, &RULE.dst.addr.v.a.addr.v6, sizeof(struct in6_addr)))) {
#ifdef USE_LIBPFCTL
			if(sscanf(RULE.label[0], PINEHOLE_LABEL_FORMAT_SKIPDESC, &uid, &ts) != 2) {
				syslog(LOG_DEBUG, "rule with label '%s' is not a IGD pinhole", RULE.label[0]);
				continue;
			}
#else /* USE_LIBPFCTL */
			if(sscanf(RULE.label, PINEHOLE_LABEL_FORMAT_SKIPDESC, &uid, &ts) != 2) {
				syslog(LOG_DEBUG, "rule with label '%s' is not a IGD pinhole", RULE.label);
				continue;
			}
#endif /* USE_LIBPFCTL */
			if(timestamp) *timestamp = ts;
			if(desc) {
#ifdef USE_LIBPFCTL
				char * p = strchr(RULE.label[0], ':');
#else /* USE_LIBPFCTL */
				char * p = strchr(RULE.label, ':');
#endif /* USE_LIBPFCTL */
				if(p) {
					p += 2;
					strlcpy(desc, p, desc_len);
				}
			}
			release_ticket(dev, tnum);
			return uid;
		}
	}
	release_ticket(dev, tnum);
	return -2;
}

static int delete_pinhole_one(unsigned short uid)
{
	int i, n;
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
	char label_start[PF_RULE_LABEL_SIZE];
	char tmp_label[PF_RULE_LABEL_SIZE];

	if(dev<0) {
		syslog(LOG_ERR, "pf device is not open");
		return -1;
	}
	snprintf(label_start, sizeof(label_start),
	         "pinhole-%hu", uid);
#ifdef USE_LIBPFCTL
	if(pfctl_get_rules_info(dev, &ri, PF_PASS, anchor_name) < 0)
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
		if(pfctl_get_rule(dev, i, ri.ticket, anchor_name, PF_PASS, &rule, anchor_call) < 0)
		{
			syslog(LOG_ERR, "pfctl_get_rule: %m");
			return -1;
		}
		strlcpy(tmp_label, RULE.label[0], sizeof(tmp_label));
#else /* USE_LIBPFCTL */
		pr.nr = i;
		if(ioctl(dev, DIOCGETRULE, &pr) < 0) {
			syslog(LOG_ERR, "ioctl(dev, DIOCGETRULE): %m");
			return -1;
		}
		strlcpy(tmp_label, RULE.label, sizeof(tmp_label));
#endif /* USE_LIBPFCTL */
		strtok(tmp_label, " ");
		if(0 == strcmp(tmp_label, label_start)) {
			if(pf_rule_remove(PF_PASS, i) < 0) {
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

int delete_pinhole(unsigned short uid)
{
	struct pinhole_rec rec;
	int r;
	/* find out if it is a pinhole of a PCP mapping */
	if(pinhole_find_uid(uid, &rec) < 0 || strncmp(rec.desc, "PCP MAP ", 8) != 0)
		return delete_pinhole_one(uid);
	/* delete all the pinholes of the mapping : found in one walk, removed
	 * from the last (a group has at most PCP_FILTER_PEER_MAX + 1, walk again
	 * if there are more) */
	{
		struct members_ctx c;
		unsigned int k;
		c.rec = &rec;
		c.members = calloc(PCP_FILTER_PEER_MAX + 1, sizeof(*c.members));
		if(c.members == NULL)
			return -1;
		do {
			c.n = 0;
			if(pinhole_foreach(members_cb, &c) < 0) {
				free(c.members);
				return -1;
			}
			for(k = c.n; k-- > 0; ) {
				if(pf_rule_remove(PF_PASS, c.members[k].index) < 0) {
					free(c.members);
					return -1;
				}
			}
		} while(c.n == PCP_FILTER_PEER_MAX + 1);
		free(c.members);
	}
	r = 0;
	return r;
}

int
get_pinhole_info(unsigned short uid,
                 char * rem_host, int rem_hostlen, unsigned short * rem_port,
                 char * int_client, int int_clientlen, unsigned short * int_port,
                 int * proto, char * desc, int desclen,
                 unsigned int * timestamp,
                 u_int64_t * packets, u_int64_t * bytes)
{
	int i, n;
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
	char label_start[PF_RULE_LABEL_SIZE];
	char tmp_label[PF_RULE_LABEL_SIZE];
	char * p;

	if(dev<0) {
		syslog(LOG_ERR, "pf device is not open");
		return -1;
	}
	snprintf(label_start, sizeof(label_start),
	         "pinhole-%hu", uid);
#ifdef USE_LIBPFCTL
	if(pfctl_get_rules_info(dev, &ri, PF_PASS, anchor_name) < 0)
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
		if(pfctl_get_rule(dev, i, ri.ticket, anchor_name, PF_PASS, &rule, anchor_call) < 0)
		{
			syslog(LOG_ERR, "pfctl_get_rule: %m");
			release_ticket(dev, tnum);
			return -1;
		}
		strlcpy(tmp_label, RULE.label[0], sizeof(tmp_label));
#else /* USE_LIBPFCTL */
		pr.nr = i;
		if(ioctl(dev, DIOCGETRULE, &pr) < 0) {
			syslog(LOG_ERR, "ioctl(dev, DIOCGETRULE): %m");
			release_ticket(dev, tnum);
			return -1;
		}
		strlcpy(tmp_label, RULE.label, sizeof(tmp_label));
#endif /* USE_LIBPFCTL */
		p = tmp_label;
		strsep(&p, " ");
		if(0 == strcmp(tmp_label, label_start)) {
			if(rem_host && (inet_ntop(AF_INET6, &RULE.src.addr.v.a.addr.v6, rem_host, rem_hostlen) == NULL)) {
				release_ticket(dev, tnum);
				return -1;
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
			if(timestamp)
				sscanf(p, "ts-%u", timestamp);
			if(desc) {
				strsep(&p, " ");
				if(p) {
					strlcpy(desc, p, desclen);
				} else {
					desc[0] = '\0';
				}
			}
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
			release_ticket(dev, tnum);
			return 0;
		}
	}
	release_ticket(dev, tnum);
	/* not found */
	return -2;
}

/* the label of a rule can not be changed : the pinhole is added again with the
 * same uid and a new timestamp, then the old one is removed.
 * The stats of the rule are reset. */
static int update_pinhole_one(const struct pinhole_rec * rec, unsigned int timestamp)
{
	char host[INET6_ADDRSTRLEN], client[INET6_ADDRSTRLEN];
	if(rec->ts == timestamp)
		return 0;
	inet_ntop(AF_INET6, &rec->src, host, sizeof(host));
	inet_ntop(AF_INET6, &rec->dst, client, sizeof(client));
	if(add_pinhole_ex(rec->uid, rec->ifname, rec->prefix ? host : NULL,
	                  rec->prefix, rec->sport, client, rec->dport, rec->proto,
	                  rec->desc, timestamp) < 0)
		return -1;
	/* the first rule of the uid is the old one */
	return delete_pinhole_one((unsigned short)rec->uid);
}

int update_pinhole(unsigned short uid, unsigned int timestamp)
{
	struct pinhole_rec rec;
	struct members_ctx c;
	unsigned int k;
	int r = 0;
	if(pinhole_find_uid(uid, &rec) < 0)
		return -2;
	if(strncmp(rec.desc, "PCP MAP ", 8) != 0)
		return update_pinhole_one(&rec, timestamp);
	/* all the pinholes of the mapping, in one pass */
	c.rec = &rec;
	c.n = 0;
	c.members = calloc(PCP_FILTER_PEER_MAX + 1, sizeof(*c.members));
	if(c.members == NULL)
		return -1;
	if(pinhole_foreach(members_cb, &c) < 0) {
		free(c.members);
		return -1;
	}
	/* add each pinhole again with the new timestamp (at the end of the
	 * rules), then remove the old ones from the last : their indices from
	 * the walk do not move. Not one walk per pinhole. */
	for(k = 0; k < c.n; k++) {
		const struct pinhole_rec * m = &c.members[k];
		char host[INET6_ADDRSTRLEN], client[INET6_ADDRSTRLEN];
		if(m->ts == timestamp)
			continue;
		inet_ntop(AF_INET6, &m->src, host, sizeof(host));
		inet_ntop(AF_INET6, &m->dst, client, sizeof(client));
		if(add_pinhole_ex(m->uid, m->ifname, m->prefix ? host : NULL,
		                  m->prefix, m->sport, client, m->dport, m->proto,
		                  m->desc, timestamp) < 0) {
			r = -1;
			break;	/* the members re-added so far : their old rule goes */
		}
	}
	while(k-- > 0) {
		if(c.members[k].ts != timestamp &&
		   pf_rule_remove(PF_PASS, c.members[k].index) < 0)
			r = -1;
	}
	free(c.members);
	return r;
}

struct clean_entry {
	int index;
	int uid;
	unsigned int ts;
	char label[PF_RULE_LABEL_SIZE];
};

struct clean_ctx {
	struct clean_entry * entries;
	unsigned int count, capacity;
};

/* collect the pinholes. They are removed after the walk because a rule
 * cannot be removed while the walk holds the ruleset ticket. */
static int
clean_collect_cb(int index, const pf_walk_rule_t * rule,
                 const struct pf_walk * walk, void * arg)
{
	struct clean_ctx * c = arg;
	struct clean_entry * e;
	int uid;
	unsigned int ts;
	UNUSED(walk);

	if(sscanf(PF_RULE_LABEL_OF(*rule), PINEHOLE_LABEL_FORMAT_SKIPDESC, &uid, &ts) != 2) {
		syslog(LOG_DEBUG, "rule with label '%s' is not a IGD pinhole", PF_RULE_LABEL_OF(*rule));
		return 0;
	}
	if(c->count == c->capacity) {
		unsigned int capacity = c->capacity ? c->capacity * 2 : 16;
		e = realloc(c->entries, capacity * sizeof(struct clean_entry));
		if(e == NULL) {
			syslog(LOG_ERR, "clean_pinhole_list: realloc(%u) failed", capacity);
			return -1;
		}
		c->entries = e;
		c->capacity = capacity;
	}
	e = &c->entries[c->count++];
	e->index = index;
	e->uid = uid;
	e->ts = ts;
	strlcpy(e->label, PF_RULE_LABEL_OF(*rule), sizeof(e->label));
	return 0;
}

/* return the number of rules removed
 * or a negative integer in case of error */
int clean_pinhole_list(unsigned int * next_timestamp)
{
	struct clean_ctx c;
	unsigned int i;
	time_t current_time;
	unsigned int min_ts = UINT_MAX;
	int min_uid = INT_MAX, max_uid = -1;
	int n = 0;

	if(dev<0) {
		syslog(LOG_ERR, "pf device is not open");
		return -1;
	}
	current_time = upnp_time();
	memset(&c, 0, sizeof(c));
	if(pf_rule_foreach(PF_PASS, clean_collect_cb, &c) != 0) {
		/* error, or stopped by a failed realloc */
		free(c.entries);
		return -1;
	}
	/* from the last rule to the first one : removing a rule does not
	 * change the index of the rules before it */
	for(i = c.count; i-- > 0; ) {
		const struct clean_entry * e = &c.entries[i];
		if(e->ts <= (unsigned int)current_time && n >= 64) {
			/* the next pass goes on, after the requests */
			min_ts = (unsigned int)current_time;
		} else if(e->ts <= (unsigned int)current_time) {
			syslog(LOG_INFO, "removing expired pinhole '%s'", e->label);
			if(pf_rule_remove(PF_PASS, e->index) < 0) {
				free(c.entries);
				return -1;
			}
			n++;
		} else {
			if(e->uid > max_uid)
				max_uid = e->uid;
			else if(e->uid < min_uid)
				min_uid = e->uid;
			if(e->ts < min_ts)
				min_ts = e->ts;
		}
	}
	free(c.entries);
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
	return n;	/* number of rules removed */
}

/* ---- for pcp_lease.c ---- */
struct state_maps_ctx {
	pcp_lease_map_cb cb;
	void * arg;
};

static int
state_maps_visit(const struct pinhole_rec * rec, void * arg)
{
	struct state_maps_ctx * c = arg;
	struct pcp_lease_map m;
	memset(&m, 0, sizeof(m));
	if(inet_ntop(AF_INET6, &rec->dst, m.iaddr, sizeof(m.iaddr)) == NULL)
		return 0;
	m.proto = rec->proto;
	m.iport = rec->dport;
	m.eport = rec->dport;	/* a pinhole has no translation */
	strlcpy(m.ifname, rec->ifname, sizeof(m.ifname));
	strlcpy(m.desc, rec->desc, sizeof(m.desc));
	m.timestamp = rec->ts;
	if(!IN6_IS_ADDR_UNSPECIFIED(&rec->src))
		inet_ntop(AF_INET6, &rec->src, m.raddr, sizeof(m.raddr));
	m.rport = rec->sport;
	c->cb(&m, c->arg);
	return 0;
}

/* call cb for each pinhole : a mapping with FILTER peers has a pinhole per peer */
int
pf_pinhole_state_maps(pcp_lease_map_cb cb, void * arg)
{
	struct state_maps_ctx c;
	c.cb = cb;
	c.arg = arg;
	return pinhole_foreach(state_maps_visit, &c);
}

#endif /* ENABLE_UPNPPINHOLE */
