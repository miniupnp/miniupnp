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

/* 1 if the firewall has the redirect rule of an IPv4 row, 0 if it has not,
 * -1 if it could not be read */
static int
map_rule_present(const struct lease_entry * e)
{
	int r = fw_map_rule(e->eport, e->proto, NULL, NULL);
	return r == 0 ? 1 : r == -2 ? 0 : -1;
}

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

	if(e->family != AF_INET)
		return -1;
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

	if(e->family != AF_INET)
		return -1;
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

	if(to->family != AF_INET)
		return -1;
	rule_of(to, &r);
	if(from->iport != to->iport)
		return update_portmapping(ext_if_name, r.eport, r.proto, r.iport, r.desc,
		                          r.timestamp);
	return update_portmapping_desc_timestamp(ext_if_name, r.eport, r.proto, r.desc,
	                                         r.timestamp);
}

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
