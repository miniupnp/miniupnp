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
	char desc_buf[64];
	const char * rhost;	/* NULL : any remote */
	const char * desc;
	unsigned short eport;
	unsigned short iport;
	int proto;
	unsigned int timestamp;
};

static void
rule_of(const struct lease_entry * e, struct fw_rule * r)
{
	if(map_ntop(e->family, &e->iaddr, r->iaddr, sizeof(r->iaddr)) == NULL)
		r->iaddr[0] = '\0';
	r->rhost = map_rhost(e, r->rhost_buf, sizeof(r->rhost_buf));
	r->desc = map_rule_desc(e, r->desc_buf, sizeof(r->desc_buf));
	r->eport = e->eport;
	r->iport = e->iport;
	r->proto = e->proto;
	r->timestamp = e->timestamp;
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

int
fw_map_rule(unsigned short eport, int proto, u_int64_t * packets, u_int64_t * bytes)
{
	unsigned short iport;
	unsigned int timestamp;
	/* get_redirect_rule() gives -2 for a rule not found and -1 for an error
	 * (iptables, nftables and pf). ipfw and ipf give -1 for not found and
	 * cannot tell an error apart */
	int r = get_redirect_rule(ext_if_name, eport, proto, NULL, 0, &iport, NULL, 0,
	                          NULL, 0, &timestamp, packets, bytes);
#if defined(USE_IPFW) || defined(USE_IPF)
	return r >= 0 ? 0 : -2;
#else
	return r >= 0 ? 0 : r == -2 ? -2 : -1;
#endif
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
	unsigned int timestamp;
	u_int64_t packets, bytes;
	int i, proto;

	for(i = 0; get_redirect_rule_by_index(i, NULL, &eport, iaddr, sizeof(iaddr),
	                                      &iport, &proto, NULL, 0, NULL, 0,
	                                      &timestamp, &packets, &bytes) >= 0; i++)
		fn(eport, proto, packets, bytes, arg);
	return 0;
#endif
}

/* 1 if the firewall has the redirect rule of an IPv4 row, 0 if it has not,
 * -1 if it could not be read */
static int
map_rule_present(const struct lease_entry * e)
{
	int r = fw_map_rule(e->eport, e->proto, NULL, NULL);
	return r == 0 ? 1 : r == -2 ? 0 : -1;
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
	char desc[64];
	struct map6_rule r;
	int i, j;

	map_rule_desc(e, desc, sizeof(desc));
	for(i = 0; i < map6_rules(e); i++) {
		map6_rule_of(e, i, &r);
		if(add_map6_rule(ext_if_name6, r.rhost, r.rport, r.iaddr, e->iport,
		                 e->proto, desc, e->timestamp) < 0)
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
fw_map6_rule(const struct lease_entry * e, int i)
{
	struct map6_rule r;
	u_int64_t packets;
	int ret;

	map6_rule_of(e, i, &r);
	ret = get_map6_packets(r.rhost, r.rport, r.iaddr, e->iport, e->proto, &packets);
	return ret == 0 ? 0 : ret == -2 ? -2 : -1;
}

int
fw_map6_packets(const struct lease_entry * e, int i, u_int64_t * packets)
{
	struct map6_rule r;

	map6_rule_of(e, i, &r);
	return get_map6_packets(r.rhost, r.rport, r.iaddr, e->iport, e->proto, packets);
}
#endif /* FW_MAP6 */

/* Delete the rules of a row. The result of the backend, or 0 if the backend
 * failed on a rule which it does not have: then the row can go. A firewall
 * which cannot be read is not taken for one without the rule: the row
 * stays, and the next delete or expiry tries again. A flush or another
 * program can remove a rule, and pf reports the missing rule as an
 * error. */
static int
delete_rules(const struct lease_entry * e)
{
	int r;

	if(e->family == AF_INET6) {
#ifdef FW_MAP6
		return delete_map6_rules(e);
#else
		return -1;
#endif
	}
#if defined(__linux__)
	r = delete_redirect_and_filter_rules(e->eport, e->proto);
#elif defined(USE_PF)
	r = delete_redirect_and_filter_rules(ext_if_name, e->eport, e->proto);
#else
	r = delete_redirect_rule(ext_if_name, e->eport, e->proto);
	delete_filter_rule(ext_if_name, e->eport, e->proto);
#endif
	if(r < 0 && map_rule_present(e) == 0) {
		syslog(LOG_INFO, "port %hu %s has no rule in the firewall, its row goes",
		       e->eport, proto_itoa(e->proto));
		return 0;
	}
	return r;
}

/* Add the rules of a row. *half is set when the redirect rule of a port
 * mapping stays although the add failed. fresh: the port had no rule before
 * the add, so a rule found after it failed is its own. The result of the
 * backend. */
static int
add_rules(const struct lease_entry * e, int * half, int fresh)
{
	struct fw_rule r;

	if(e->family == AF_INET6) {
#ifdef FW_MAP6
		UNUSED(fresh);
		return add_map6_rules(e, half);
#else
		return -1;
#endif
	}
	rule_of(e, &r);
	if(add_redirect_rule2(ext_if_name, r.rhost, r.eport, r.iaddr, r.iport, r.proto,
	                      r.desc, r.timestamp) < 0) {
		/* A backend which adds more than one rule takes back the first
		 * when a later one fails, and that can fail too: iptables adds a
		 * MASQUERADE rule after the DNAT rule */
		if(fresh && map_rule_present(e) == 1) {
			syslog(LOG_WARNING, "the add of port %hu failed, and its redirect rule stays",
			       r.eport);
			*half = 1;
		}
		return -1;
	}
	if(add_filter_rule2(ext_if_name, r.rhost, r.iaddr, r.eport, r.iport, r.proto,
	                    r.desc) >= 0)
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

/* Change the rules of from into those of to. The result of the backend. */
static int
update_rules(const struct lease_entry * from, const struct lease_entry * to)
{
	struct fw_rule r;

	/* a map6 rule holds no expiry nor description: the table has them */
	if(to->family == AF_INET6)
		return 0;
	rule_of(to, &r);
	if(from->iport != to->iport)
		return update_portmapping(ext_if_name, r.eport, r.proto, r.iport, r.desc,
		                          r.timestamp);
	return update_portmapping_desc_timestamp(ext_if_name, r.eport, r.proto, r.desc,
	                                         r.timestamp);
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
	char desc[64];
	const char * ifname = ext_if_name;

#ifdef ENABLE_IPV6
	if(b->family == AF_INET6)
		ifname = ext_if_name6;
#endif
	if(map_ntop(b->family, &b->iaddr, iaddr, sizeof(iaddr)) == NULL ||
	   map_ntop(b->family, &b->eaddr, eaddr, sizeof(eaddr)) == NULL ||
	   map_ntop(b->family, &p->raddr, raddr, sizeof(raddr)) == NULL)
		return -1;
	outgoing_rule_desc(b, desc, sizeof(desc));
#ifdef PCP_FLOWP
	if(c->dscp_up &&
	   add_peer_dscp_rule2(ifname, raddr, p->rport, c->dscp_up, iaddr, b->iport,
	                       b->proto, desc, p->timestamp) < 0)
		return -1;
	if(c->dscp_down &&
	   add_peer_dscp_rule2(ifname, iaddr, b->iport, c->dscp_down, raddr, p->rport,
	                       b->proto, desc, p->timestamp) < 0) {
		*half = c->dscp_up != 0;
		return -1;
	}
#endif
	if(add_peer_redirect_rule2(ifname, raddr, p->rport, eaddr, b->eport, iaddr,
	                           b->iport, b->proto, desc, p->timestamp) < 0) {
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
