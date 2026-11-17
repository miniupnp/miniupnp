/* fw_sync(): turn the rows of a request into the rules of the firewall in
 * use. See fwsync.h. */
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "config.h"
#include "macros.h"
#include "upnpglobalvars.h"
#include "fwsync.h"
#if defined(USE_NETFILTER)
#include "netfilter/iptcrdr.h"
#ifdef USE_NFTABLES
#include "netfilter_nft/nftnlrdr.h"
#endif
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
	char raddr[INET6_ADDRSTRLEN];
	const char * rhost;	/* NULL : any remote */
	unsigned short rport;
	unsigned short eport;
	unsigned short iport;
	int proto;
	const char * desc;
	unsigned int timestamp;
};

/* the address of a row, IPv4 kept as ::ffff:a.b.c.d */
static void
addr_str(int family, const struct in6_addr * a, char * s, size_t len)
{
	if(family == AF_INET)
		inet_ntop(AF_INET, a->s6_addr + 12, s, len);
	else
		inet_ntop(AF_INET6, a, s, len);
}

static void
rule_of(const struct lease_entry * e, struct fw_rule * r)
{
	memset(r, 0, sizeof(*r));
	addr_str(e->family, &e->iaddr, r->iaddr, sizeof(r->iaddr));
	if(e->remote != NULL) {
		addr_str(e->family, &e->remote->raddr, r->raddr, sizeof(r->raddr));
		r->rhost = r->raddr;
		r->rport = e->remote->rport;
	}
	r->eport = e->eport;
	r->iport = e->iport;
	r->proto = e->proto;
	r->desc = e->label != NULL ? e->label : "";
	r->timestamp = (unsigned int)e->expiry;
}

/* Delete the rules of a row. The result of the backend. */
static int
delete_rules(const struct lease_entry * e, unsigned short uid)
{
	int r;

	if(e->family == AF_INET6) {
#ifdef FW_PINHOLES
		return delete_pinhole(uid);
#else
		UNUSED(uid);
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
	return r;
}

/* Add the rules of a row. *half is set when the redirect rule of a port
 * mapping stays although its filter rule failed. The result of the backend. */
static int
add_rules(const struct lease_entry * e, unsigned short * uid, int * half)
{
	struct fw_rule r;
	int ret;

	rule_of(e, &r);
	if(e->family == AF_INET6) {
#if defined(FW_PINHOLES)
		ret = add_pinhole(ext_if_name6, r.rhost, r.rport, r.iaddr, r.iport,
		                  r.proto, r.desc, r.timestamp);
		if(ret < 0)
			return -1;
		*uid = (unsigned short)ret;
		return 0;
#else
		return -1;
#endif
	}
	if(add_redirect_rule2(ext_if_name, r.rhost, r.eport, r.iaddr, r.iport, r.proto,
	                      r.desc, r.timestamp) < 0)
		return -1;
	if(add_filter_rule2(ext_if_name, r.rhost, r.iaddr, r.eport, r.iport, r.proto,
	                    r.desc) >= 0)
		return 0;
	/* the redirect rule goes again */
#if defined(__linux__)
	ret = delete_redirect_and_filter_rules(r.eport, r.proto);
#else
	ret = delete_redirect_rule(ext_if_name, r.eport, r.proto);
#endif
	if(ret < 0) {
		syslog(LOG_WARNING, "could not remove the half added rule of port %hu", r.eport);
		*half = 1;
	}
	return -1;
}

/* Change the rules of from into those of to. The result of the backend. */
static int
update_rules(const struct lease_entry * from, const struct lease_entry * to,
             unsigned short uid)
{
	struct fw_rule r;
	if(to->family == AF_INET6) {
#ifdef FW_PINHOLES
		UNUSED(from);
		return update_pinhole(uid, (unsigned int)to->expiry);
#else
		UNUSED(from); UNUSED(uid);
		return -1;
#endif
	}
	rule_of(to, &r);
	if(from->iport != to->iport)
		return update_portmapping(ext_if_name, r.eport, r.proto, r.iport, r.desc,
		                          r.timestamp);
	return update_portmapping_desc_timestamp(ext_if_name, r.eport, r.proto, r.desc,
	                                         r.timestamp);
}

/* Send one change. The result of the backend, and *half as for add_rules(). */
static int
send_change(struct fw_change * c, int * half)
{
	switch(c->op) {
	case FW_ADD:
		return add_rules(c->row, &c->uid, half);
	case FW_UPDATE:
		return update_rules(c->old, c->row, c->uid);
	case FW_DELETE:
		return delete_rules(c->old, c->uid);
	}
	return -1;
}

/* Take back a change the firewall applied. 0, or < 0 if it stays. */
static int
undo_change(struct fw_change * c)
{
	int half = 0;
	/* with only the key of the rule, its old form is not known */
	if(c->old_partial && c->op != FW_ADD)
		return -1;
	switch(c->op) {
	case FW_ADD:
		return delete_rules(c->row, c->uid);
	case FW_UPDATE:
		return update_rules(c->row, c->old, c->uid);
	case FW_DELETE:
		/* the backend gives a pinhole a new uid, so it cannot come back as it was */
		if(c->old->family == AF_INET6)
			return -1;
		return add_rules(c->old, &c->uid, &half);
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
