/* MiniUPnP project
 * PCP MAP FILTER policy for the pf backend.
 * This software is subject to the conditions detailed in the LICENCE file.
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
#include <stdint.h>
#include <time.h>
#ifdef USE_LIBPFCTL
#include <libpfctl.h>
#endif

#include "../macros.h"
#include "obsdrdr.h"
#include "../upnpglobalvars.h"
#include "rtickets.h"
#include "../pcp_filter.h"
#include "pfpcp.h"
#include "pfrules.h"

#ifdef USE_PF

/* /dev/pf when opened */
extern int dev;

/* PCP MAP FILTER (RFC 6887 section 13.3) :
 * a filtered mapping is a group of rdr (and pass) rules, one per allowed
 * remote peer prefix/port, so traffic from other sources is never translated.
 * A policy for a mapping which is about to be created is kept pending until
 * add_redirect_rule2() and add_filter_rule2() have consumed it. */

struct pf_pcp_policy * pending_policy = NULL;

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
unsigned int
pf_pcp_pending_filters4(const char * iaddr, unsigned short iport, int proto,
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
	return pf_rule_remove(PF_RDR, index);
}

static void
policy_iaddr_str(const struct in6_addr * address, char * buf, size_t len)
{
	inet_ntop(AF_INET, address->s6_addr + 12, buf, len);
}

struct read_group_ctx {
	const char * want;
	unsigned short port;
	unsigned char protocol;
	struct pf_pcp_policy * policy;
	struct pf_group_template * tpl;
};

static int
read_group_cb(int index, const char * ifname, unsigned short eport,
              const char * iaddr, unsigned short iport, int proto,
              const char * desc, in_addr_t saddr, unsigned int prefix,
              unsigned short sport, unsigned int timestamp, void * arg)
{
	struct read_group_ctx * c = arg;
	struct pf_pcp_policy * policy = c->policy;
	struct pf_group_template * tpl = c->tpl;
	UNUSED(index); UNUSED(timestamp);
	if(iport != c->port || proto != c->protocol || strcmp(iaddr, c->want) != 0)
		return 0;
	if(tpl->nrules++ == 0)
	{
		tpl->eport = eport;
		strlcpy(tpl->desc, desc, sizeof(tpl->desc));
		strlcpy(tpl->ifname, ifname, sizeof(tpl->ifname));
	}
	/* a rule with any address but a source port is a filter too */
	if((prefix > 0 || sport != 0) && policy->count < PCP_FILTER_PEER_MAX)
	{
		struct pcp_filter * f = &policy->filters[policy->count++];
		memset(&f->address, 0, sizeof(f->address));
		f->address.s6_addr[10] = f->address.s6_addr[11] = 0xff;
		memcpy(f->address.s6_addr + 12, &saddr, 4);
		f->prefix = prefix + 96;
		f->port = sport;
	}
	return 0;
}

/* read the rules of a mapping : the policy and the parameters of its rules.
 * returns the number of rules */
static unsigned int
read_group(const struct in6_addr * address, unsigned short port,
           unsigned char protocol,
           struct pf_pcp_policy * policy, struct pf_group_template * tpl)
{
	char want[INET_ADDRSTRLEN];
	struct read_group_ctx c;
	memset(policy, 0, sizeof(*policy));
	memset(tpl, 0, sizeof(*tpl));
	policy->address = *address;
	policy->port = port;
	policy->protocol = protocol;
	policy_iaddr_str(address, want, sizeof(want));
	c.want = want;
	c.port = port;
	c.protocol = protocol;
	c.policy = policy;
	c.tpl = tpl;
	get_redirect_rules_foreach(read_group_cb, &c);
	return tpl->nrules;
}

struct src_entry {
	in_addr_t addr;	/* network byte order */
	unsigned int prefix;
	unsigned short port;
};

/* the source of the unfiltered rule : any address, any port */
static void
any_filter(int v4, struct pcp_filter * f)
{
	memset(f, 0, sizeof(*f));
	if(v4)
	{
		f->address.s6_addr[10] = f->address.s6_addr[11] = 0xff;
		f->prefix = 96;
	}
}

/* k-th source of the rules of a policy (the unfiltered rule if no filter) */
static void
policy_filter(const struct pf_pcp_policy * policy, unsigned int k, int v4,
              struct pcp_filter * f)
{
	if(policy->count)
		*f = policy->filters[k];
	else
		any_filter(v4, f);
}

static int
policy_has_filter(const struct pf_pcp_policy * policy, const struct pcp_filter * f,
                  int v4)
{
	unsigned int k, n = policy->count ? policy->count : 1;
	struct pcp_filter o;
	for(k = 0; k < n; k++)
	{
		policy_filter(policy, k, v4, &o);
		if(pcp_filter_equal(&o, f))
			return 1;
	}
	return 0;
}

typedef int (*filter_cb)(const struct pcp_filter * f, void * ctx);

/* change the rules of a mapping from the policy 'from' to the policy 'to' :
 * add() is called for the missing sources first, then del() for the obsolete
 * ones. At the first add() error the sources added so far are removed again
 * (add() must not leave a partial source behind) and -1 is returned. */
static int
policy_diff(const struct pf_pcp_policy * to, const struct pf_pcp_policy * from,
            int v4, filter_cb add, filter_cb del, void * ctx)
{
	unsigned int k, n;
	struct pcp_filter f;
	n = to->count ? to->count : 1;
	for(k = 0; k < n; k++)
	{
		policy_filter(to, k, v4, &f);
		if(policy_has_filter(from, &f, v4))
			continue;
		if(add(&f, ctx) < 0)
		{
			/* undo the sources added by this call so the mapping
			 * keeps the policy 'from' */
			unsigned int j;
			for(j = 0; j < k; j++)
			{
				policy_filter(to, j, v4, &f);
				if(!policy_has_filter(from, &f, v4))
					del(&f, ctx);
			}
			return -1;
		}
	}
	n = from->count ? from->count : 1;
	for(k = 0; k < n; k++)
	{
		policy_filter(from, k, v4, &f);
		if(policy_has_filter(to, &f, v4))
			continue;
		del(&f, ctx);
	}
	return 0;
}

static void
filter_to_src(const struct pcp_filter * f, struct src_entry * e)
{
	memset(e, 0, sizeof(*e));
	memcpy(&e->addr, f->address.s6_addr + 12, 4);
	e->prefix = f->prefix - 96;
	e->port = f->port;
}

struct remove_group_ctx {
	const char * want;
	unsigned short port;
	unsigned char protocol;
	const struct src_entry * e;
	int index;
};

static int
remove_group_cb(int index, const char * ifname, unsigned short eport,
                const char * iaddr, unsigned short iport, int proto,
                const char * desc, in_addr_t saddr, unsigned int prefix,
                unsigned short sport, unsigned int timestamp, void * arg)
{
	struct remove_group_ctx * c = arg;
	UNUSED(ifname); UNUSED(eport); UNUSED(desc); UNUSED(timestamp);
	if(iport == c->port && proto == c->protocol && strcmp(iaddr, c->want) == 0 &&
	   prefix == c->e->prefix && sport == c->e->port &&
	   (saddr & prefix_to_mask4(prefix)) ==
	       (c->e->addr & prefix_to_mask4(prefix)))
	{
		c->index = index;
		return 1;
	}
	return 0;
}

/* remove the rdr rule of the mapping having this source */
static int
remove_group_rule(const struct in6_addr * address, unsigned short port,
                  unsigned char protocol, const struct src_entry * e)
{
	char want[INET_ADDRSTRLEN];
	struct remove_group_ctx c;
	policy_iaddr_str(address, want, sizeof(want));
	c.want = want;
	c.port = port;
	c.protocol = protocol;
	c.e = e;
	c.index = -1;
	if(get_redirect_rules_foreach(remove_group_cb, &c) != 1)
		return -1;
	return remove_rdr_rule_at(c.index);
}

struct group4_ctx {
	const struct pf_pcp_policy * to;
	const struct pf_group_template * tpl;
	char iaddr[INET_ADDRSTRLEN];
};

static int
group4_add(const struct pcp_filter * f, void * ctx)
{
	struct group4_ctx * c = ctx;
	struct src_entry e;
	int r;
	filter_to_src(f, &e);
	r = add_redirect_rule_ex(c->tpl->ifname, e.addr, e.prefix, e.port, c->tpl->eport,
	                         c->iaddr, c->to->port, c->to->protocol, c->tpl->desc);
	if(r == 0)
	{
		r = add_filter_rule_ex(c->tpl->ifname, e.addr, e.prefix, e.port, c->iaddr,
		                       c->tpl->eport, c->to->port, c->to->protocol, c->tpl->desc);
		if(r < 0)	/* do not keep a rdr rule without its pass rule */
			remove_group_rule(&c->to->address, c->to->port, c->to->protocol, &e);
	}
	return r;
}

static int
group4_remove(const struct pcp_filter * f, void * ctx)
{
	struct group4_ctx * c = ctx;
	struct src_entry e;
	struct in_addr a;
	filter_to_src(f, &e);
	remove_group_rule(&c->to->address, c->to->port, c->to->protocol, &e);
	inet_pton(AF_INET, c->iaddr, &a);
	filter_src_match.active = 1;
	filter_src_match.addr = e.addr;
	filter_src_match.prefix = e.prefix;
	filter_src_match.port = e.port;
	priv_delete_filter_rule(c->tpl->ifname, c->to->port, c->to->protocol, a.s_addr);
	filter_src_match.active = 0;
	return 0;
}

/* change the rules of a mapping from the policy 'from' to the policy 'to' */
static int
group_apply(const struct pf_pcp_policy * to, const struct pf_pcp_policy * from,
            const struct pf_group_template * tpl)
{
	struct group4_ctx c;
	c.to = to;
	c.tpl = tpl;
	policy_iaddr_str(&to->address, c.iaddr, sizeof(c.iaddr));
	return policy_diff(to, from, 1, group4_add, group4_remove, &c);
}

/* ---- IPv6 : the policy is stored in the pinholes of the mapping ---- */
#ifdef ENABLE_UPNPPINHOLE
struct group6_ctx {
	const struct pf_pcp_policy * to;
	const char * ifname;
	const char * desc;
	unsigned int timestamp;
};

/* an unfiltered policy is passed to the pinhole functions as NULL */
static const struct pcp_filter *
pinhole_filter(const struct pcp_filter * f)
{
	return f->prefix ? f : NULL;
}

static int
group6_add(const struct pcp_filter * f, void * ctx)
{
	struct group6_ctx * c = ctx;
	return pf_pinhole_group_add(c->ifname, &c->to->address, c->to->port,
	                            c->to->protocol, c->desc, c->timestamp,
	                            pinhole_filter(f));
}

static int
group6_remove(const struct pcp_filter * f, void * ctx)
{
	struct group6_ctx * c = ctx;
	return pf_pinhole_group_remove(&c->to->address, c->to->port,
	                               c->to->protocol, pinhole_filter(f));
}

static int
group_apply6(const struct pf_pcp_policy * to, const struct pf_pcp_policy * from,
             const char * ifname, const char * desc, unsigned int timestamp)
{
	struct group6_ctx c;
	c.to = to;
	c.ifname = ifname;
	c.desc = desc;
	c.timestamp = timestamp;
	return policy_diff(to, from, 0, group6_add, group6_remove, &c);
}

#endif /* ENABLE_UPNPPINHOLE */

/* merge the options of a request in a policy (RFC 6887 section 13.3) :
 * a FILTER with a prefix length of 0 removes all the peers.
 * returns 0, -1 (invalid) or -2 (too many peers) */
static int
policy_merge(struct pf_pcp_policy * p, const struct pcp_filter * filters,
             unsigned int count, int v4)
{
	return pcp_filter_merge(p->filters, &p->count, filters, count, v4);
}

/* the peers of a mapping which does not exist yet are kept until its rules
 * are created */
static void
set_pending_policy(struct pf_pcp_policy * policy)
{
	free(pending_policy);
	pending_policy = policy;
}

/* IPv4 mapping : the policy is in its rdr and pass rules.
 * returns 0, -1 (error) or -2 (too many peers) */
static int
begin4(const struct in6_addr * address, unsigned short port,
       unsigned char protocol, const struct pcp_filter * filters,
       unsigned int count, struct pcp_filter_update * u,
       struct pf_pcp_policy * merged)
{
	struct pf_group_template tpl;
	int r;
	u->existing = read_group(address, port, protocol, &u->old, &tpl) > 0;
	*merged = u->old;
	r = policy_merge(merged, filters, count, 1);
	if(r < 0)
		return r;
	if(!u->existing)
		return 0;	/* the rules will be created with the mapping */
	/* rewrite the rules of the existing mapping */
	if(merged->count != u->old.count ||
	   memcmp(merged->filters, u->old.filters,
	          merged->count * sizeof(merged->filters[0])) != 0)
	{
		if(group_apply(merged, &u->old, &tpl) < 0)
			return -1;
	}
	return 0;
}

#ifdef ENABLE_UPNPPINHOLE
/* IPv6 mapping : the policy is in its pinholes.
 * returns 0, -1 (error) or -2 (too many peers) */
static int
begin6(const struct in6_addr * address, unsigned short port,
       unsigned char protocol, const struct pcp_filter * filters,
       unsigned int count, struct pcp_filter_update * u,
       struct pf_pcp_policy * merged)
{
	char desc[PF_RULE_LABEL_SIZE], ifn[IFNAMSIZ];
	unsigned int ts = 0;
	int r;
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
	if(r < 0)
		return r;
	if(u->existing && group_apply6(merged, &u->old, ifn, desc, ts) < 0)
		return -1;
	return 0;
}
#endif /* ENABLE_UPNPPINHOLE */

/* returns 0 : OK
 *        -1 : error
 *        -2 : too many peers
 *        -3 : not supported (IPv6 address without pinholes) */
int
pf_pcp_filter_begin(const struct in6_addr * address, unsigned short port,
                    unsigned char protocol, const char * ifname,
                    const struct pcp_filter * filters, unsigned int count,
                    struct pcp_filter_update ** update)
{
	struct pcp_filter_update * u;
	struct pf_pcp_policy * merged;
	int r;
	UNUSED(ifname);
	*update = NULL;
	u = calloc(1, sizeof(*u));
	merged = calloc(1, sizeof(*merged));
	if(u == NULL || merged == NULL)
		r = -1;
	else if(IN6_IS_ADDR_V4MAPPED(address))
		r = begin4(address, port, protocol, filters, count, u, merged);
#ifdef ENABLE_UPNPPINHOLE
	else
		r = begin6(address, port, protocol, filters, count, u, merged);
#else
	else
		r = -3;
#endif
	if(r < 0)
	{
		free(u);
		free(merged);
		return r;
	}
	if(u->existing)
		free(merged);
	else
		set_pending_policy(merged);
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


/* ---- for pcp_lease.c ---- */
struct state_maps_ctx {
	pcp_lease_map_cb cb;
	void * arg;
};

static int
state_maps_cb(int index, const char * ifname, unsigned short eport,
              const char * iaddr, unsigned short iport, int proto,
              const char * desc, in_addr_t saddr, unsigned int prefix,
              unsigned short sport, unsigned int timestamp, void * arg)
{
	struct state_maps_ctx * c = arg;
	struct pcp_lease_map m;
	UNUSED(index); UNUSED(saddr); UNUSED(prefix); UNUSED(sport);
	memset(&m, 0, sizeof(m));
	m.proto = proto;
	m.eport = eport;
	m.iport = iport;
	strlcpy(m.iaddr, iaddr, sizeof(m.iaddr));
	strlcpy(m.ifname, ifname, sizeof(m.ifname));
	strlcpy(m.desc, desc, sizeof(m.desc));
	m.timestamp = timestamp;
	c->cb(&m, c->arg);
	return 0;
}

/* a mapping with FILTER peers has a rdr rule per peer, and is reported
 * once per rule */
int
pf_pcp_lease_maps(pcp_lease_map_cb cb, void * arg)
{
	struct state_maps_ctx c;
	int r;
	c.cb = cb;
	c.arg = arg;
	r = get_redirect_rules_foreach(state_maps_cb, &c);
#ifdef ENABLE_UPNPPINHOLE
	pf_pinhole_state_maps(cb, arg);	/* the IPv6 mappings */
#endif
	return r;
}

/* the IPv4 mapping to an internal endpoint (iport 0 : any port), in one pass
 * over the rdr rules. returns 0 if found */
struct find_map_ctx {
	const char * iaddr;
	unsigned short iport;
	int proto;
	unsigned short * eport;
	char * desc;
	int desclen;
	unsigned int * timestamp;
	int found;
};

static int
find_map_cb(int index, const char * ifname, unsigned short eport,
            const char * iaddr, unsigned short iport, int proto,
            const char * desc, in_addr_t saddr, unsigned int prefix,
            unsigned short sport, unsigned int timestamp, void * arg)
{
	struct find_map_ctx * c = arg;
	UNUSED(index); UNUSED(ifname); UNUSED(saddr); UNUSED(prefix); UNUSED(sport);
	if(proto != c->proto || (c->iport != 0 && iport != c->iport) ||
	   strcmp(iaddr, c->iaddr) != 0)
		return 0;
	*c->eport = eport;
	if(c->desc != NULL && c->desclen > 0)
		strlcpy(c->desc, desc, c->desclen);
	if(c->timestamp != NULL)
		*c->timestamp = timestamp;
	c->found = 1;
	return 1;
}

int
pf_pcp_find_map(const char * iaddr, unsigned short iport, int proto,
                unsigned short * eport, char * desc, int desclen,
                unsigned int * timestamp)
{
	struct find_map_ctx c;
	c.iaddr = iaddr;
	c.iport = iport;
	c.proto = proto;
	c.eport = eport;
	c.desc = desc;
	c.desclen = desclen;
	c.timestamp = timestamp;
	c.found = 0;
	get_redirect_rules_foreach(find_map_cb, &c);
	return c.found ? 0 : -1;
}

/* A save of the PCP lease file asks for the peers of every mapping. One walk
 * per mapping would be N x N, so for the time of a save the peers are read once
 * into a hash table on the mapping. */
#define FILTER_INDEX_SIZE 4096
struct filter_index_entry {
	struct filter_index_entry * next;
	struct in6_addr address;
	unsigned short port;
	unsigned char protocol;
	struct pcp_filter filter;
};
static struct filter_index_entry * filter_index[FILTER_INDEX_SIZE];
static int filter_index_active, filter_index_built, filter_index_failed;

static unsigned int
filter_index_bucket(const struct in6_addr * address, unsigned short port,
                    unsigned char protocol)
{
	unsigned int h = 2166136261u, i;
	for(i = 0; i < sizeof(address->s6_addr); i++)
		h = (h ^ address->s6_addr[i]) * 16777619u;
	h = (h ^ port) * 16777619u;
	h = (h ^ protocol) * 16777619u;
	return h % FILTER_INDEX_SIZE;
}

/* add a peer of a mapping to the index */
void
pf_pcp_filter_index_add(const struct in6_addr * address, unsigned short port,
                        unsigned char protocol, const struct pcp_filter * f)
{
	struct filter_index_entry * e = malloc(sizeof(*e));
	unsigned int b = filter_index_bucket(address, port, protocol);
	if(e == NULL)
	{
		filter_index_failed = 1;
		return;
	}
	e->address = *address;
	e->port = port;
	e->protocol = protocol;
	e->filter = *f;
	e->next = filter_index[b];
	filter_index[b] = e;
}

static int
filter_index_cb(int index, const char * ifname, unsigned short eport,
                const char * iaddr, unsigned short iport, int proto,
                const char * desc, in_addr_t saddr, unsigned int prefix,
                unsigned short sport, unsigned int timestamp, void * arg)
{
	struct in6_addr address;
	struct in_addr ia;
	struct pcp_filter f;
	UNUSED(index); UNUSED(ifname); UNUSED(eport); UNUSED(desc);
	UNUSED(timestamp); UNUSED(arg);
	/* as read_group_cb() */
	if((prefix == 0 && sport == 0) || inet_pton(AF_INET, iaddr, &ia) != 1)
		return 0;
	memset(&address, 0, sizeof(address));
	address.s6_addr[10] = address.s6_addr[11] = 0xff;
	memcpy(address.s6_addr + 12, &ia, 4);
	memset(&f, 0, sizeof(f));
	f.address = address;
	memcpy(f.address.s6_addr + 12, &saddr, 4);
	f.prefix = prefix + 96;
	f.port = sport;
	pf_pcp_filter_index_add(&address, iport, (unsigned char)proto, &f);
	return 0;
}

static void
filter_index_free(void)
{
	unsigned int b;
	for(b = 0; b < FILTER_INDEX_SIZE; b++)
	{
		while(filter_index[b] != NULL)
		{
			struct filter_index_entry * e = filter_index[b];
			filter_index[b] = e->next;
			free(e);
		}
	}
}

/* the peers of a mapping from the index, in the order of the rules */
static unsigned int
filter_index_get(const struct in6_addr * address, unsigned short port,
                 unsigned char protocol, struct pcp_filter * filters,
                 unsigned int max)
{
	const struct filter_index_entry * e;
	unsigned int n = 0, i;
	for(e = filter_index[filter_index_bucket(address, port, protocol)];
	    e != NULL && n < max; e = e->next)
	{
		if(e->port == port && e->protocol == protocol &&
		   memcmp(&e->address, address, sizeof(*address)) == 0)
			filters[n++] = e->filter;
	}
	for(i = 0; i < n / 2; i++)
	{
		struct pcp_filter f = filters[i];
		filters[i] = filters[n - 1 - i];
		filters[n - 1 - i] = f;
	}
	return n;
}

void
pf_pcp_save_begin(void)
{
	pf_rule_snapshot_begin();
	filter_index_active = 1;
	filter_index_built = 0;
	filter_index_failed = 0;
}

void
pf_pcp_save_end(void)
{
	filter_index_active = 0;
	filter_index_free();
	pf_rule_snapshot_end();
}

/* the FILTER peers of a mapping, IPv4 or IPv6 */
unsigned int
pf_pcp_filter_get(const struct in6_addr * address, unsigned short port,
                  unsigned char protocol, struct pcp_filter * filters,
                  unsigned int max)
{
	struct pf_pcp_policy policy;
	struct pf_group_template tpl;
	unsigned int n;
	if(filter_index_active && !filter_index_built)
	{
		filter_index_built = 1;
		if(get_redirect_rules_foreach(filter_index_cb, NULL) < 0)
			filter_index_failed = 1;
#ifdef ENABLE_UPNPPINHOLE
		if(pf_pinhole_group_index() < 0)
			filter_index_failed = 1;
#endif
	}
	if(filter_index_active && !filter_index_failed)
		return filter_index_get(address, port, protocol, filters, max);
	if(!IN6_IS_ADDR_V4MAPPED(address))
	{
#ifdef ENABLE_UPNPPINHOLE
		unsigned int count = 0;
		pf_pinhole_group_get(address, port, protocol, filters, max, &count,
		                     NULL, 0, NULL, NULL);
		return count;
#else
		return 0;
#endif
	}
	read_group(address, port, protocol, &policy, &tpl);
	n = policy.count < max ? policy.count : max;
	memcpy(filters, policy.filters, n * sizeof(*filters));
	return n;
}

#endif /* USE_PF */
