/* MiniUPnP project
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

/* fw_sync(): turn the rows of a request into the rules of the firewall in
 * use. See fwsync.h. */
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "macros.h"
#include "config.h"
#include "upnpglobalvars.h"
#include "upnputils.h"
#include "fwsync.h"
#if defined(USE_NETFILTER)
#include "netfilter/iptcrdr.h"
#endif
#if defined(USE_PF)
#include "pf/obsdrdr.h"
#endif
#if defined(USE_IPF)
#include "ipf/ipfrdr.h"
#endif
#if defined(USE_IPFW)
#include "ipfw/ipfwrdr.h"
#endif
#ifdef FW_MAP6
#include "fwmap6.h"
#endif

/* a row as the arguments of the backend functions */
struct fw_rule {
	char iaddr[INET6_ADDRSTRLEN];
	char rhost_buf[INET6_ADDRSTRLEN];
	const char * rhost;	/* NULL : any remote */
	unsigned short eport;
	unsigned short iport;
	int proto;
};

static void
rule_of(const struct lease_entry * e, struct fw_rule * r)
{
	if(map_ntop(e->family, &e->iaddr, r->iaddr, sizeof(r->iaddr)) == NULL)
		r->iaddr[0] = '\0';
	r->rhost = map_rhost(e, r->rhost_buf, sizeof(r->rhost_buf));
	r->eport = e->eport;
	r->iport = e->iport;
	r->proto = e->proto;
}

void
fw_change_init(struct fw_change * c, enum fw_op op,
               const struct lease_entry * row, const struct lease_entry * old)
{
	memset(c, 0, sizeof(*c));
	c->op = op;
	c->row = row;
	c->old = old;
}

/* The result of get_redirect_rule() as 0, -2 for a rule not found or -1
 * for an error. iptables, nftables and pf give these. ipfw and ipf give -1
 * for not found and cannot tell an error apart. */
static int
redirect_result(int r)
{
#if defined(USE_IPFW) || defined(USE_IPF)
	return r >= 0 ? 0 : -2;
#else
	return r >= 0 ? 0 : r == -2 ? -2 : -1;
#endif
}

int
fw_map_rule(unsigned short eport, int proto, u_int64_t * packets, u_int64_t * bytes)
{
	unsigned short iport;

	return redirect_result(get_redirect_rule(ext_if_name, eport, proto, NULL, 0,
	                                         &iport, NULL, 0,
	                                         packets, bytes));
}

int
fw_each_map_counters(fw_counters_fn fn, void * arg)
{
#if defined(USE_IPTABLES)
	/* one copy of the nat table, where a read by index copies it each time */
	return get_redirect_rules_counters(fn, arg);
#else
	char iaddr[INET6_ADDRSTRLEN];
	unsigned short eport, iport;
	u_int64_t packets, bytes;
	int i, proto;

	for(i = 0; get_redirect_rule_by_index(i, NULL, &eport, iaddr, sizeof(iaddr),
	                                      &iport, &proto, NULL, 0, &packets, &bytes) >= 0; i++)
		fn(eport, proto, packets, bytes, arg);
	return 0;
#endif
}

#ifdef FW_MAP6
/* The key of the rule of filter i of the IPv6 map e, as the arguments of
 * the map6 functions. An IPv6 map has one rule per filter, and a map with
 * no filter one rule of any remote. */
struct map6_rule {
	char iaddr[INET6_ADDRSTRLEN];
	char raddr[INET6_ADDRSTRLEN];
	const char * rhost;	/* NULL : any remote */
	unsigned short rport;
};

static void
map6_rule_of(const struct lease_entry * e, int i, struct map6_rule * r)
{
	static const struct map_filter any_remote;
	const struct map_filter * f = e->nfilters > 0 ? &e->filters[i] : &any_remote;

	if(map_ntop(AF_INET6, &e->iaddr, r->iaddr, sizeof(r->iaddr)) == NULL)
		r->iaddr[0] = '\0';
	r->rhost = NULL;
	if(f->prefix != 0 &&
	   map_ntop(AF_INET6, &f->raddr, r->raddr, sizeof(r->raddr)) != NULL)
		r->rhost = r->raddr;
	r->rport = f->rport;
}

/* the number of rules of the IPv6 map e */
static int
map6_rules(const struct lease_entry * e)
{
	return e->nfilters > 0 ? e->nfilters : 1;
}

/* Delete the rule of filter i of e. 0 also when the firewall has no such
 * rule: it went without the daemon. */
static int
delete_map6_filter(const struct lease_entry * e, int i)
{
	struct map6_rule r;
	int ret;

	map6_rule_of(e, i, &r);
	ret = delete_map6_rule(r.rhost, r.rport, r.iaddr, e->iport, e->proto);
	return ret == -2 ? 0 : ret;
}

/* Delete the rules of every filter of the IPv6 map e. A rule which is gone
 * already counts as deleted, so a retry after a part failed finishes the
 * others. 0, or the first error. */
static int
delete_map6_rules(const struct lease_entry * e)
{
	int i, r, ret = 0;

	for(i = 0; i < map6_rules(e); i++) {
		r = delete_map6_filter(e, i);
		if(r < 0 && ret == 0)
			ret = r;
	}
	return ret;
}

/* Add the rules of every filter of the IPv6 map e, one per filter, which
 * may be hundreds for a PCP MAP with FILTER options. When one fails, the
 * rules before it go again: *half is set if one of them stays. */
static int
add_map6_rules(const struct lease_entry * e, int * half)
{
	struct map6_rule r;
	int i, j;

	for(i = 0; i < map6_rules(e); i++) {
		map6_rule_of(e, i, &r);
		if(add_map6_rule(ext_if_name6, r.rhost, r.rport, r.iaddr, e->iport,
		                 e->proto) < 0)
			break;
	}
	if(i == map6_rules(e))
		return 0;
	syslog(LOG_WARNING, "map6 [%s]:%hu: the rule of filter %d of %d failed",
	       r.iaddr, e->iport, i + 1, map6_rules(e));
	for(j = 0; j < i; j++) {
		if(delete_map6_filter(e, j) < 0)
			*half = 1;
	}
	return -1;
}

int
fw_map6_packets(const struct lease_entry * e, int i, u_int64_t * packets)
{
	struct map6_rule r;

	map6_rule_of(e, i, &r);
	return get_map6_packets(r.rhost, r.rport, r.iaddr, e->iport, e->proto, packets);
}
#else
static int
delete_map6_rules(const struct lease_entry * e)
{
	UNUSED(e);
	return -1;
}

static int
add_map6_rules(const struct lease_entry * e, int * half)
{
	UNUSED(e); UNUSED(half);
	return -1;
}
#endif /* FW_MAP6 */

/* Delete the rules of an IPv4 port mapping. The result of the backend, or 0
 * if the backend failed on a rule which it does not have: then the row can
 * go. A firewall which cannot be read is not taken for one without the
 * rule: the row stays, and the next delete or expiry tries again. A flush
 * or another program can remove a rule, and pf reports the missing rule as
 * an error. */
static int
delete_map4_rules(const struct lease_entry * e)
{
	int r;

#if defined(__linux__)
	r = delete_redirect_and_filter_rules(e->eport, e->proto);
#elif defined(USE_PF)
	r = delete_redirect_and_filter_rules(ext_if_name, e->eport, e->proto);
#else
	r = delete_redirect_rule(ext_if_name, e->eport, e->proto);
	delete_filter_rule(ext_if_name, e->eport, e->proto);
#endif
	if(r < 0 && fw_map_rule(e->eport, e->proto, NULL, NULL) == -2) {
		syslog(LOG_INFO, "port %hu %s has no rule in the firewall, its row goes",
		       e->eport, proto_itoa(e->proto));
		return 0;
	}
	return r;
}

/* Delete the rules of a row, as delete_map4_rules() */
static int
delete_rules(const struct lease_entry * e)
{
	return e->family == AF_INET6 ? delete_map6_rules(e) : delete_map4_rules(e);
}

/* Add the rules of an IPv4 port mapping. *half is set when its redirect
 * rule stays although the add failed. fresh: the port had no rule before
 * the add, so a rule found after it failed is its own. The result of the
 * backend. */
static int
add_map4_rules(const struct lease_entry * e, int * half, int fresh)
{
	struct fw_rule r;

	rule_of(e, &r);
	if(add_redirect_rule2(ext_if_name, r.rhost, r.eport, r.iaddr, r.iport, r.proto) < 0) {
		/* A backend which adds more than one rule takes back the first
		 * when a later one fails, and that can fail too: iptables adds a
		 * MASQUERADE rule after the DNAT rule */
		if(fresh && fw_map_rule(e->eport, e->proto, NULL, NULL) == 0) {
			syslog(LOG_WARNING, "the add of port %hu failed, and its redirect rule stays",
			       r.eport);
			*half = 1;
		}
		return -1;
	}
	if(add_filter_rule2(ext_if_name, r.rhost, r.iaddr, r.eport, r.iport, r.proto) >= 0)
		return 0;
	/* the redirect rule goes again. Only that rule: the filter rule of
	 * another mapping to the same iaddr:iport, or a PEER rule on eport,
	 * stays. If it stays, so does a row of it, which the expiry deletes. */
	if(delete_redirect_rule(ext_if_name, r.eport, r.proto) < 0) {
		syslog(LOG_WARNING, "could not remove the half added rule of port %hu", r.eport);
		*half = 1;
	}
	return -1;
}

/* Add the rules of a row, as add_map4_rules() and add_map6_rules() */
static int
add_rules(const struct lease_entry * e, int * half, int fresh)
{
	if(e->family == AF_INET6)
		return add_map6_rules(e, half);
	return add_map4_rules(e, half, fresh);
}

/* Change the rules of from into those of to. The result of the backend. */
static int
update_rules(const struct lease_entry * from, const struct lease_entry * to)
{
	struct fw_rule r;

	/* a map6 rule holds no expiry nor description: the table has them */
	if(to->family == AF_INET6)
		return 0;
	rule_of(to, &r);
	/* the rule holds no expiry: a renewal changes it only for a new
	 * internal port */
	if(from->iport == to->iport)
		return 0;
	return update_portmapping(ext_if_name, r.eport, r.proto, r.iport);
}

#if defined(PCP_PEER) && defined(USE_NETFILTER)
/* Add the PEER rule of b to its peer p, after its DSCP rules (PCP
 * FLOWDATA). *half is set when a DSCP rule stays although the add failed:
 * no function deletes a DSCP rule alone. */
static int
add_peer_rules(const struct fw_out_change * c, int * half)
{
	const struct outgoing_entry * b = c->b;
	const struct outgoing_peer * p = &b->peers[c->peer];
	char iaddr[INET6_ADDRSTRLEN], eaddr[INET6_ADDRSTRLEN], raddr[INET6_ADDRSTRLEN];
	const char * ifname = ext_if_name;

#ifdef ENABLE_IPV6
	if(b->family == AF_INET6)
		ifname = ext_if_name6;
#endif
	if(map_ntop(b->family, &b->iaddr, iaddr, sizeof(iaddr)) == NULL ||
	   map_ntop(b->family, &b->eaddr, eaddr, sizeof(eaddr)) == NULL ||
	   map_ntop(b->family, &p->raddr, raddr, sizeof(raddr)) == NULL)
		return -1;
#ifdef PCP_FLOWP
	if(c->dscp_up &&
	   add_peer_dscp_rule2(ifname, raddr, p->rport, c->dscp_up, iaddr, b->iport,
	                       b->proto) < 0)
		return -1;
	if(c->dscp_down &&
	   add_peer_dscp_rule2(ifname, iaddr, b->iport, c->dscp_down, raddr, p->rport,
	                       b->proto) < 0) {
		*half = c->dscp_up != 0;
		return -1;
	}
#endif
	if(add_peer_redirect_rule2(ifname, raddr, p->rport, eaddr, b->eport, iaddr,
	                           b->iport, b->proto) < 0) {
		*half = c->dscp_up != 0 || c->dscp_down != 0;
		return -1;
	}
	return 0;
}

/* Delete the PEER rule of peer c->peer of c->b, with its DSCP rules,
 * found by its full key: the other peers of the binding and a map on its
 * port keep theirs. 0 also when the firewall no longer has it. */
static int
delete_peer_rules(const struct fw_out_change * c)
{
	const struct outgoing_entry * b = c->b;
	const struct outgoing_peer * p = &b->peers[c->peer];
	struct outgoing_rule_key k;

	/* no IPv6 PEER rules */
	if(!IN6_IS_ADDR_V4MAPPED(&b->iaddr) || !IN6_IS_ADDR_V4MAPPED(&p->raddr))
		return 0;
	memset(&k, 0, sizeof(k));
	memcpy(&k.iaddr, &b->iaddr.s6_addr[12], sizeof(k.iaddr));
	memcpy(&k.raddr, &p->raddr.s6_addr[12], sizeof(k.raddr));
	k.iport = b->iport;
	k.rport = p->rport;
	k.eport = b->eport;
	k.proto = b->proto;
	if(outgoing_rule_delete(&k, 1) < 0)
		return -1;
	if(k.result != 0)
		syslog(LOG_INFO, "PEER port %hu %s has no rule in the firewall, its peer goes",
		       b->eport, proto_itoa(b->proto));
	return 0;
}
#else
static int
add_peer_rules(const struct fw_out_change * c, int * half)
{
	UNUSED(c); UNUSED(half);
	return -1;
}

static int
delete_peer_rules(const struct fw_out_change * c)
{
	UNUSED(c);
	return -1;
}
#endif

/* Send one change. The result of the backend, and *half as for add_rules(). */
static int
send_change(const struct fw_change * c, int * half)
{
	switch(c->op) {
	case FW_ADD:
		return add_rules(c->row, half, c->fresh);
	case FW_UPDATE:
		return update_rules(c->old, c->row);
	case FW_DELETE:
		return delete_rules(c->old);
	}
	return -1;
}

/* Take back a change the firewall applied. 0, or < 0 if it stays. A delete
 * whose rules come back in part is FW_HALF_APPLIED. */
static int
undo_change(struct fw_change * c)
{
	int half = 0, r;

	switch(c->op) {
	case FW_ADD:
		return delete_rules(c->row);
	case FW_UPDATE:
		return update_rules(c->row, c->old);
	case FW_DELETE:
		r = add_rules(c->old, &half, 1);
		if(half)
			c->applied = FW_HALF_APPLIED;
		return r;
	}
	return -1;
}

/* One rule at a time, and the changes before a failure taken back. */
int
fw_sync(struct fw_change * c, int n)
{
	int i, r = 0, half;

	for(i = 0; i < n; i++)
		c[i].applied = FW_NOT_APPLIED;
	for(i = 0; i < n; i++) {
		half = 0;
		r = send_change(&c[i], &half);
		if(r < 0) {
			if(half)
				c[i].applied = FW_HALF_APPLIED;
			break;
		}
		c[i].applied = FW_APPLIED;
	}
	if(i == n)
		return 0;
	syslog(LOG_WARNING, "fw_sync: change %d of %d failed (%d)", i + 1, n, r);
	while(i-- > 0) {
		if(undo_change(&c[i]) >= 0)
			c[i].applied = FW_NOT_APPLIED;
		else
			syslog(LOG_WARNING, "fw_sync: change %d of %d stays", i + 1, n);
	}
	return r < 0 ? r : -1;
}

void
fw_out_change_init(struct fw_out_change * c, enum fw_out_op op,
                   const struct outgoing_entry * b, int peer)
{
	memset(c, 0, sizeof(*c));
	c->op = op;
	c->b = b;
	c->peer = peer;
}

static int
send_out_change(const struct fw_out_change * c, int * half)
{
	switch(c->op) {
	case FW_OUT_ADD:
		return add_peer_rules(c, half);
	case FW_OUT_DELETE:
		return delete_peer_rules(c);
	}
	return -1;
}

static int
undo_out_change(struct fw_out_change * c)
{
	int half = 0, r;

	switch(c->op) {
	case FW_OUT_ADD:
		return delete_peer_rules(c);
	case FW_OUT_DELETE:
		r = add_peer_rules(c, &half);
		if(half)
			c->applied = FW_HALF_APPLIED;
		return r;
	}
	return -1;
}

/* As fw_sync(), for the outgoing changes. */
int
fw_sync_out(struct fw_out_change * c, int n)
{
	int i, r = 0, half;

	for(i = 0; i < n; i++)
		c[i].applied = FW_NOT_APPLIED;
	for(i = 0; i < n; i++) {
		half = 0;
		r = send_out_change(&c[i], &half);
		if(r < 0) {
			if(half)
				c[i].applied = FW_HALF_APPLIED;
			break;
		}
		c[i].applied = FW_APPLIED;
	}
	if(i == n)
		return 0;
	syslog(LOG_WARNING, "fw_sync_out: change %d of %d failed (%d)", i + 1, n, r);
	while(i-- > 0) {
		if(undo_out_change(&c[i]) >= 0)
			c[i].applied = FW_NOT_APPLIED;
		else
			syslog(LOG_WARNING, "fw_sync_out: change %d of %d stays", i + 1, n);
	}
	return r < 0 ? r : -1;
}

/* The internal side and the remote host of an IPv4 redirect rule into e, a
 * row of lease_table_new(1). 0, or -1 if the rule holds no IPv4 address. */
static int
map_row_of_rule(struct lease_entry * e, const char * iaddr, unsigned short iport,
                const char * rhost)
{
	if(map_ipv4_to_ipv6_af(iaddr, AF_INET, &e->iaddr) < 0 ||
	   e->filters_alloc < 1 || map_filter_set(&e->filters[0], rhost, 0) < 0)
		return -1;
	e->family = AF_INET;
	e->iport = iport;
	e->nfilters = e->filters[0].prefix != 0 ? 1 : 0;
	return 0;
}

int
fw_read_map(struct lease_entry * e)
{
	char iaddr[INET6_ADDRSTRLEN];
	char rhost[INET6_ADDRSTRLEN];
	unsigned short iport;
	int r;

	iaddr[0] = rhost[0] = '\0';
	r = redirect_result(get_redirect_rule(ext_if_name, e->eport, e->proto,
	                                      iaddr, sizeof(iaddr), &iport, rhost, sizeof(rhost), 0, 0));
	if(r != 0)
		return r;
	return map_row_of_rule(e, iaddr, iport, rhost);
}

int
fw_map_rule_at(int i, struct lease_entry * e)
{
	char iaddr[INET6_ADDRSTRLEN];
	char rhost[INET6_ADDRSTRLEN];
	unsigned short eport, iport;
	u_int64_t packets, bytes;
	int proto;

	iaddr[0] = rhost[0] = '\0';
	if(get_redirect_rule_by_index(i, NULL, &eport, iaddr, sizeof(iaddr), &iport,
	                              &proto, rhost, sizeof(rhost), &packets, &bytes) < 0)
		return -1;
	e->eport = eport;
	e->proto = proto;
	return map_row_of_rule(e, iaddr, iport, rhost) < 0 ? 1 : 0;
}

#ifdef FW_MAP6
int
fw_map6_rule_at(int i, struct lease_entry * e)
{
	char rhost[INET6_ADDRSTRLEN];
	char iaddr[INET6_ADDRSTRLEN];
	unsigned short rport, iport;
	int proto;

	rhost[0] = iaddr[0] = '\0';
	if(get_map6_rule_at(i, rhost, sizeof(rhost), &rport, iaddr, sizeof(iaddr),
	                    &iport, &proto) < 0)
		return -1;
	if(map_ipv4_to_ipv6_af(iaddr, AF_INET6, &e->iaddr) < 0 ||
	   e->filters_alloc < 1 || map_filter_set(&e->filters[0], rhost, rport) < 0)
		return 1;
	e->family = AF_INET6;
	e->proto = proto;
	e->iport = e->eport = iport;	/* a map6 has no translation */
	/* the rule of any remote is that of a map with no filter */
	e->nfilters = e->filters[0].prefix != 0 || e->filters[0].rport != 0 ? 1 : 0;
	return 0;
}
#endif

#if defined(PCP_PEER) && defined(USE_NETFILTER)
int
fw_peer_rule_at(int i, struct outgoing_entry * b)
{
	char iaddr[INET6_ADDRSTRLEN];
	char rhost[INET6_ADDRSTRLEN];
	unsigned short eport, iport, rport;
	int proto;

	iaddr[0] = rhost[0] = '\0';
	if(get_peer_rule_by_index(i, NULL, &eport, iaddr, sizeof(iaddr), &iport, &proto, rhost, sizeof(rhost), &rport,
	                          NULL, NULL) < 0)
		return -1;
	if(map_ipv4_to_ipv6_af(iaddr, AF_INET, &b->iaddr) < 0 ||
	   map_ipv4_to_ipv6_af(rhost, AF_INET, &b->peers[0].raddr) < 0)
		return 1;
	b->family = AF_INET;
	b->proto = proto;
	b->eport = eport;
	b->iport = iport;
	b->peers[0].rport = rport;
	b->npeers = 1;
	return 0;
}
#endif

/* the IPv4 mapping e: 0, 1, -1 or -2 as fw_check_row() */
static int
check_map4(struct lease_entry * e)
{
	struct lease_entry rule;	/* the rule the firewall has, on the stack */
	struct map_filter f;
	struct lease_entry * fw = &rule;
	struct fw_change c[2];
	int r, n = 0;

	lease_entry_init(fw, 0, NULL);
	fw->filters = &f;
	fw->filters_alloc = 1;
	fw->proto = e->proto;
	fw->eport = e->eport;
	if(e->fw_partial) {
		/* only a part of the rules is there: send them all again */
		syslog(LOG_NOTICE, "port mapping %hu %s has a part of its rules, sending them again",
		       e->eport, proto_itoa(e->proto));
		fw_change_init(&c[n++], FW_DELETE, NULL, e);
		r = -2;
	} else {
		r = fw_read_map(fw);
		if(r == -1 || (r == 0 && IN6_ARE_ADDR_EQUAL(&fw->iaddr, &e->iaddr) &&
		               fw->iport == e->iport))
			return r;	/* unreadable, or as the row says */
	}
	if(r == 0) {
		/* another program pointed the port elsewhere: its rule goes,
		 * the row's comes back, in one request */
		syslog(LOG_NOTICE, "port mapping %hu %s points elsewhere, putting it back",
		       e->eport, proto_itoa(e->proto));
		fw_change_init(&c[n++], FW_DELETE, NULL, fw);
	} else if(!e->fw_partial) {
		syslog(LOG_NOTICE, "port mapping %hu %s lost its rule, adding it back",
		       e->eport, proto_itoa(e->proto));
	}
	fw_change_init(&c[n], FW_ADD, e, NULL);
	c[n].fresh = 1;
	n++;
	r = fw_sync(c, n);
	/* a failed send leaves a part: that of the add, or the part there
	 * was, when its delete failed */
	if(r == 0)
		e->fw_partial = 0;
	else if(c[n - 1].applied != FW_NOT_APPLIED)
		e->fw_partial = 1;
	return r == 0 ? 1 : -2;
}

#ifdef FW_MAP6
/* the IPv6 map e: 0, 1, -1 or -2 as fw_check_row(). The key of a map6
 * rule is its target, so it cannot point elsewhere: only gone. */
static int
check_map6(struct lease_entry * e)
{
	struct fw_change c[2];
	u_int64_t packets;
	int i, r, unknown = 0;

	/* only a part of the rules is there: send them all again */
	for(i = 0; !e->fw_partial && i < map6_rules(e); i++) {
		r = fw_map6_packets(e, i, &packets);
		if(r == -2)
			break;
		if(r < 0)
			unknown = 1;
	}
	if(!e->fw_partial && i == map6_rules(e))
		return unknown ? -1 : 0;
	syslog(LOG_NOTICE, "map6 port %hu %s lost its rules, adding them back",
	       e->iport, proto_itoa(e->proto));
	/* what is left of them goes, then all come back, in one request */
	fw_change_init(&c[0], FW_DELETE, NULL, e);
	fw_change_init(&c[1], FW_ADD, e, NULL);
	r = fw_sync(c, 2);
	/* as check_map4(): a part there was stays a part */
	if(r == 0)
		e->fw_partial = 0;
	else if(c[1].applied != FW_NOT_APPLIED)
		e->fw_partial = 1;
	return r == 0 ? 1 : -2;
}
#else
static int
check_map6(struct lease_entry * e)
{
	UNUSED(e);
	return -1;
}
#endif

int
fw_check_row(struct lease_entry * e)
{
	return e->family == AF_INET6 ? check_map6(e) : check_map4(e);
}
