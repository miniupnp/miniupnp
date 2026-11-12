/* The layer between the protocols and the mapping table. See memmap.h.
 *
 * Functions this file gets later:
 * memmap_add_filter()	the third add: a FILTER peer on the row of a PCP MAP.
 * memmap_sync()	send the rows of a request to the firewall as one
 *			transaction. A request succeeds or fails as a whole. Its
 *			rows are built in full and are not linked into the table:
 *			a success links them, and a failure frees them, so a
 *			lookup never finds a row the firewall refused. The startup
 *			restore, a firewall reload and rules lost from the
 *			firewall use the same send. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "config.h"
#include "macros.h"
#include "upnpredirect.h"
#include "upnpglobalvars.h"
#include "upnputils.h"
#include "lease_table.h"
#include "memmap.h"
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

/* The firewalls which have pinholes. The PF API of Apple differs from what
 * pf/pfpinhole.c expects. */
#ifdef ENABLE_UPNPPINHOLE
#if defined(USE_NETFILTER) || (defined(USE_PF) && !defined(__APPLE__))
#define MEMMAP_PINHOLES
#if defined(USE_NETFILTER)
#include "netfilter/iptpinhole.h"
#else
#include "pf/pfpinhole.h"
#endif
#endif
#endif


/* The table keeps every address in 16 bytes: turn a.b.c.d into ::ffff:a.b.c.d.
 * 0, or -1 if s is not an IPv4 address */
static int
v4_mapped(const char * s, struct in6_addr * a)
{
	struct in_addr v4;
	if(inet_pton(AF_INET, s, &v4) != 1)
		return -1;
	memset(a, 0, sizeof(*a));
	a->s6_addr[10] = a->s6_addr[11] = 0xff;
	memcpy(a->s6_addr + 12, &v4, sizeof(v4));
	return 0;
}

/* the value of a hex digit. mapping_owner_of() has checked the digits */
static int
hex_value(int c)
{
	if(c >= '0' && c <= '9') return c - '0';
	if(c >= 'a' && c <= 'f') return c - 'a' + 10;
	return c - 'A' + 10;
}

/* Set the owner of a row, its kind and nonce, from the description of its rule.
 * A PCP description ends in the 24 hex digits of the nonce. See
 * mapping_owner_of(). */
static void
set_owner(struct lease_entry * e, const char * desc, unsigned short eport, int proto)
{
	int i;
	memset(e->nonce, 0, sizeof(e->nonce));
	switch(mapping_owner_of(desc, eport, proto)) {
	case MAPPING_PCP:
		e->kind = LEASE_PCP_MAP;
		desc += strlen(desc) - 24;
		for(i = 0; i < LEASE_NONCE_LEN; i++)
			e->nonce[i] = (unsigned char)(hex_value(desc[2 * i]) * 16 +
			                              hex_value(desc[2 * i + 1]));
		break;
	case MAPPING_NATPMP:
		e->kind = LEASE_NATPMP;
		break;
	default:
		e->kind = LEASE_UPNP;
	}
}

/* the kind of row which mapping_owner_of() gives for owner */
static unsigned char
owner_kind(int owner)
{
	switch(owner) {
	case MAPPING_PCP:
		return LEASE_PCP_MAP;
	case MAPPING_NATPMP:
		return LEASE_NATPMP;
	default:
		return LEASE_UPNP;
	}
}

/* Add the row of an IPv4 port mapping, with its remote peer if remote is set,
 * or renew it. */
static void
ipv4_row(const char * remote, unsigned short rport, unsigned short eport,
         const char * iaddr, unsigned short iport, int proto,
         const char * desc, unsigned int timestamp)
{
	struct lease_entry e, * row, * old;
	struct in6_addr raddr;
	int has_remote = remote != NULL && v4_mapped(remote, &raddr) == 0;

	memset(&e, 0, sizeof(e));
	if(v4_mapped(iaddr, &e.iaddr) < 0)
		return;
	set_owner(&e, desc ? desc : "", eport, proto);
	/* An IPv4 port has one row, whatever its remote: UPnP maps an external
	 * port once, and a PCP PEER has no row. A row with another remote is
	 * replaced. */
	old = lease_table_find_mapping(proto, AF_INET, NULL, eport);
	if(old != NULL && old->iport == iport && lease_table_same_owner(old, &e) &&
	   memcmp(&old->iaddr, &e.iaddr, sizeof(e.iaddr)) == 0 &&
	   (old->remote == NULL ? !has_remote
	                        : has_remote && old->remote->rport == rport &&
	                          memcmp(&old->remote->raddr, &raddr, sizeof(raddr)) == 0)) {
		/* a renewal : the row stays, and keeps its place in the list */
		old->expiry = timestamp;
		if(lease_table_set_label(old, desc) < 0)
			syslog(LOG_WARNING, "lease table: no memory for the label of %hu", eport);
		syslog(LOG_DEBUG, "memmap: renew %s port %hu, expiry %u", proto_itoa(proto), eport,
		       timestamp);
		return;
	}
	if(old != NULL)
		syslog(LOG_DEBUG, "memmap: replace the row of %s port %hu", proto_itoa(proto), eport);
	e.family = AF_INET;
	e.proto = (unsigned char)proto;
	e.eport = eport;
	e.iport = iport;
	e.expiry = timestamp;
	e.label = (char *)desc;	/* copied */
	/* another row on the port is replaced. If that fails, it stays: the port
	 * is still mapped */
	if(old != NULL)
		row = lease_table_replace(old, &e, has_remote ? &raddr : NULL, rport);
	else
		row = lease_table_add(&e, has_remote ? &raddr : NULL, rport);
	if(row == NULL)
		syslog(LOG_WARNING, "lease table: could not add %hu %d", eport, proto);
	else
		syslog(LOG_INFO, "memmap: add %s port %hu to %s:%hu, remote %s, expiry %u",
		       proto_itoa(proto), eport, iaddr, iport, has_remote ? remote : "any",
		       timestamp);
}

/* Remove the row of an IPv4 mapping: the one row of its port. */
void
memmap_map_gone(unsigned short eport, int proto)
{
	struct lease_entry * row = lease_table_find_mapping(proto, AF_INET, NULL, eport);
	if(row != NULL) {
		lease_table_remove(row);
		syslog(LOG_INFO, "memmap: remove %s port %hu", proto_itoa(proto), eport);
	}
}

/* Find the first IPv4 mapping of an internal endpoint. */
int
memmap_find_map(const char * iaddr, unsigned short iport, int proto,
                int owner, unsigned short * eport, char * desc, int desclen,
                unsigned int * timestamp)
{
	struct in6_addr a;
	const struct lease_entry * row;
	if(v4_mapped(iaddr, &a) < 0)
		return -1;
	for(row = lease_table_next_internal(NULL, proto, AF_INET, &a, iport); row != NULL;
	    row = lease_table_next_internal(row, proto, AF_INET, &a, iport)) {
		if(owner >= 0 && row->kind != owner_kind(owner))
			continue;
		*eport = row->eport;
		if(desc != NULL && desclen > 0)
			snprintf(desc, desclen, "%s", row->label ? row->label : "");
		if(timestamp != NULL)
			*timestamp = (unsigned int)row->expiry;
		syslog(LOG_DEBUG, "memmap: %s %s:%hu has external port %hu", proto_itoa(proto),
		       iaddr, iport, row->eport);
		return 0;
	}
	syslog(LOG_DEBUG, "memmap: no mapping of %s %s:%hu", proto_itoa(proto), iaddr, iport);
	return -1;
}

/* Return the expiry of an IPv4 mapping. */
unsigned int
memmap_map_expiry(unsigned short eport, int proto)
{
	struct lease_entry * row = lease_table_find_mapping(proto, AF_INET, NULL, eport);
	return row != NULL ? (unsigned int)row->expiry : 0;
}

/* Add the row of an IPv6 pinhole, with its remote peer if raddr is set, or renew
 * it. */
static void
ipv6_row(unsigned short uid, const char * raddr, unsigned short rport,
         const char * iaddr, unsigned short iport, int proto,
         const char * desc, unsigned int timestamp)
{
	struct lease_entry e, * row = lease_table_find_uid(uid);
	struct in6_addr r, i;
	int has_remote;

	if(row != NULL && desc == NULL) {
		row->expiry = timestamp;
		return;
	}
	if(iaddr == NULL || inet_pton(AF_INET6, iaddr, &i) != 1)
		return;
	has_remote = raddr != NULL && raddr[0] != '\0' &&
	             inet_pton(AF_INET6, raddr, &r) == 1;
	/* PCP has no uid : the row of this rule is by its key */
	if(row == NULL)
		row = lease_table_find_external(proto, AF_INET6, &i, iport,
		                                has_remote ? &r : NULL, rport);
	if(row != NULL) {
		/* a renewal : the row stays */
		if(desc != NULL && row->label != NULL && strcmp(desc, row->label) == 0 &&
		   row->iport == iport && memcmp(&row->iaddr, &i, sizeof(i)) == 0) {
			row->expiry = timestamp;
			syslog(LOG_DEBUG, "memmap: renew pinhole %s [%s]:%hu, expiry %u",
			       proto_itoa(proto), iaddr, iport, timestamp);
			return;
		}
		syslog(LOG_DEBUG, "memmap: replace the row of pinhole %s [%s]:%hu",
		       proto_itoa(proto), iaddr, iport);
	}
	memset(&e, 0, sizeof(e));
	e.iaddr = e.eaddr = i;
	e.family = AF_INET6;
	e.proto = (unsigned char)proto;
	e.eport = e.iport = iport;
	e.expiry = timestamp;
	e.label = (char *)desc;
	set_owner(&e, desc ? desc : "", iport, proto);
	if(e.kind == LEASE_UPNP)
		lease_set_uid(&e, uid);
	/* if the row cannot be replaced, it stays: the rule is still there */
	if(row != NULL)
		row = lease_table_replace(row, &e, has_remote ? &r : NULL, rport);
	else
		row = lease_table_add(&e, has_remote ? &r : NULL, rport);
	if(row == NULL)
		syslog(LOG_WARNING, "lease table: could not add Remote peer %hu", uid);
	else
		syslog(LOG_INFO, "memmap: add pinhole %s [%s]:%hu, uid %hu, remote %s port %hu, expiry %u",
		       proto_itoa(proto), iaddr, iport, uid, has_remote ? raddr : "any", rport,
		       timestamp);
}

/* Add the row of a mapping with no remote peer, or renew it. */
void
memmap_map(unsigned short uid, unsigned short eport, const char * iaddr,
           unsigned short iport, int proto, const char * desc,
           unsigned int timestamp)
{
	if(strchr(iaddr, ':') != NULL)
		ipv6_row(uid, NULL, 0, iaddr, iport, proto, desc, timestamp);
	else
		ipv4_row(NULL, 0, eport, iaddr, iport, proto, desc, timestamp);
}

/* Add the row of a mapping with its Remote peer, or renew it. */
void
memmap_remote_peer(unsigned short uid, const char * raddr, unsigned short rport,
                   unsigned short eport, const char * iaddr, unsigned short iport,
                   int proto, const char * desc, unsigned int timestamp)
{
	if(strchr(iaddr, ':') != NULL)
		ipv6_row(uid, raddr, rport, iaddr, iport, proto, desc, timestamp);
	else
		ipv4_row(raddr, rport, eport, iaddr, iport, proto, desc, timestamp);
}

/* Give the row of a UPnP pinhole a new expiry. */
void
memmap_renew_uid(unsigned short uid, unsigned int timestamp)
{
	struct lease_entry * row = lease_table_find_uid(uid);
	if(row != NULL) {
		row->expiry = timestamp;
		syslog(LOG_DEBUG, "memmap: renew pinhole uid %hu, expiry %u", uid, timestamp);
	}
}

/* Remove the row of a pinhole by its uid. */
void
memmap_remote_peer_gone(unsigned short uid)
{
	struct lease_entry * row = lease_table_find_uid(uid);
	if(row != NULL) {
		lease_table_remove(row);
		syslog(LOG_INFO, "memmap: remove pinhole uid %hu", uid);
	}
}

/* Remove the row of a pinhole by its uid, or else by its rule. */
void
memmap_remote_peer_gone_at(unsigned short uid, const char * raddr, unsigned short rport,
                           const char * iaddr, unsigned short iport, int proto)
{
	struct lease_entry * row = lease_table_find_uid(uid);
	struct in6_addr a, r;
	/* the firewall gives :: for a rule with no remote */
	int has_remote = raddr != NULL && raddr[0] != '\0' &&
	                 inet_pton(AF_INET6, raddr, &r) == 1 &&
	                 !IN6_IS_ADDR_UNSPECIFIED(&r);
	if(row != NULL) {
		lease_table_remove(row);
		syslog(LOG_INFO, "memmap: remove pinhole uid %hu", uid);
		return;
	}
	if(inet_pton(AF_INET6, iaddr, &a) != 1)
		return;
	row = lease_table_find_external(proto, AF_INET6, &a, iport,
	                                has_remote ? &r : NULL, rport);
	if(row != NULL) {
		lease_table_remove(row);
		syslog(LOG_INFO, "memmap: remove pinhole %s [%s]:%hu", proto_itoa(proto), iaddr, iport);
	}
}

/* A row cannot go during lease_table_foreach(), so a walk collects up to this
 * many rows, removes them, and walks again until it found fewer. */
#define PINHOLE_EXPIRE_MAX	256

/* what a walk over the rows gives pinhole_expiry_row() and gets back */
struct pinhole_expiry {
	time_t now;
	unsigned int n;
	struct lease_entry * rows[PINHOLE_EXPIRE_MAX];
};

/* collect the row if it is a pinhole past its expiry */
static void
pinhole_expiry_row(struct lease_entry * e, void * arg)
{
	struct pinhole_expiry * c = arg;
	if(e->family == AF_INET6 && e->expiry != 0 && e->expiry <= c->now &&
	   c->n < PINHOLE_EXPIRE_MAX)
		c->rows[c->n++] = e;
}

/* set by memmap_remote_peers_partial(), read and cleared by memmap_remote_peers_expired() */
static int pinholes_partial;

/* Keep the rows of the next pass over the pinholes. */
void
memmap_remote_peers_partial(void)
{
	pinholes_partial = 1;
	syslog(LOG_DEBUG, "memmap: expired pinhole rules are left in the firewall");
}

/* The firewall ended a pass over the pinholes, and removed "removed" rules
 * (<0 : error). The rows which expired go, as their rules went. If the pass
 * removed nothing, failed or was partial, the rows stay for the next pass: a row
 * must not go while its rule may still be there. */
static void
memmap_remote_peers_expired(unsigned int now, int removed)
{
	static struct pinhole_expiry c;
	unsigned int i, total = 0;
	int partial = pinholes_partial;

	pinholes_partial = 0;
	if(removed <= 0 || partial) {
		if(removed != 0 || partial)
			syslog(LOG_DEBUG, "memmap: keep the expired pinhole rows, removed %d, partial %d",
			       removed, partial);
		return;
	}
	do {
		c.now = now;
		c.n = 0;
		lease_table_foreach(pinhole_expiry_row, &c);
		for(i = 0; i < c.n; i++)
			lease_table_remove(c.rows[i]);
		total += c.n;
	} while(c.n == PINHOLE_EXPIRE_MAX);
	syslog(LOG_INFO, "memmap: %u expired pinhole rows removed", total);
}

#ifdef USE_NFTABLES
/* what a walk over the rows gives expiry_row() and gets back */
struct expiry_ctx {
	unsigned int now;
	struct expired_redirect * expired;
	int max;
	int n;
	unsigned int next;
};

/* Collect an IPv4 row past its expiry. Else keep the soonest expiry, so the main
 * loop knows when to come back. When expired[] is full, the next pass is now. */
static void
expiry_row(struct lease_entry * e, void * arg)
{
	struct expiry_ctx * c = arg;
	unsigned int ts = (unsigned int)e->expiry;
	if(e->family != AF_INET || ts == 0)
		return;
	if(ts > c->now) {
		if(c->next == 0 || ts < c->next)
			c->next = ts;
	} else if(c->n == c->max) {
		c->next = c->now;	/* the next pass goes on */
	} else {
		c->expired[c->n].eport = e->eport;
		c->expired[c->n++].proto = e->proto;
	}
}

/* The port mappings which expired, with no read of the firewall. */
int
memmap_expired_maps(unsigned int now, struct expired_redirect * expired,
                    int max, unsigned int * next)
{
	struct expiry_ctx c = { now, expired, max, 0, 0 };
	lease_table_foreach(expiry_row, &c);
	*next = c.next;
	if(c.n > 0)
		syslog(LOG_DEBUG, "memmap: %d port mappings expired, next at %u", c.n, c.next);
	return c.n;
}
#endif /* USE_NFTABLES */

/* 1 if the IPv4 mapping has a row */
static int
memmap_map_known(unsigned short eport, int proto)
{
	return lease_table_find_mapping(proto, AF_INET, NULL, eport) != NULL;
}

/* Copy a row of a port mapping out as strings, for memmap_get_map() and
 * memmap_get_map_at(). NULL for what is not wanted. */
static void
port_info(const struct lease_entry * row, unsigned short * iport,
          char * iaddr, int iaddrlen, char * desc, int desclen,
          char * rhost, int rhostlen, unsigned int * timestamp)
{
	if(iport != NULL)
		*iport = row->iport;
	if(iaddr != NULL && iaddrlen > 0)
		inet_ntop(AF_INET, row->iaddr.s6_addr + 12, iaddr, iaddrlen);
	if(desc != NULL && desclen > 0)
		snprintf(desc, desclen, "%s", row->label ? row->label : "");
	if(rhost != NULL && rhostlen > 0) {
		rhost[0] = '\0';
		if(row->remote != NULL)
			inet_ntop(AF_INET, row->remote->raddr.s6_addr + 12, rhost, rhostlen);
	}
	if(timestamp != NULL)
		*timestamp = (unsigned int)row->expiry;
}

/* Read an IPv4 mapping by its external port. */
int
memmap_get_map(unsigned short eport, int proto, unsigned short * iport,
               char * iaddr, int iaddrlen, char * desc, int desclen,
               char * rhost, int rhostlen, unsigned int * timestamp)
{
	const struct lease_entry * row = lease_table_find_mapping(proto, AF_INET, NULL, eport);
	if(row == NULL) {
		syslog(LOG_DEBUG, "memmap: no mapping of %s port %hu", proto_itoa(proto), eport);
		return -1;
	}
	port_info(row, iport, iaddr, iaddrlen, desc, desclen, rhost, rhostlen, timestamp);
	syslog(LOG_DEBUG, "memmap: read %s port %hu", proto_itoa(proto), eport);
	return 0;
}

/* Read an IPv4 mapping by its place on the port list. */
int
memmap_get_map_at(unsigned int index, unsigned short * eport, int * proto,
                  unsigned short * iport, char * iaddr, int iaddrlen,
                  char * desc, int desclen, char * rhost, int rhostlen,
                  unsigned int * timestamp)
{
	const struct lease_entry * row = lease_table_port_at(index);
	if(row == NULL) {
		syslog(LOG_DEBUG, "memmap: no mapping at index %u", index);
		return -1;
	}
	*eport = row->eport;
	*proto = row->proto;
	port_info(row, iport, iaddr, iaddrlen, desc, desclen, rhost, rhostlen, timestamp);
	return 0;
}

/* Return the number of IPv4 port mappings. */
int
memmap_map_count(void)
{
	return (int)lease_table_port_count();
}

/* List the external ports of a protocol in a range. */
unsigned short *
memmap_ports_in_range(unsigned short startport, unsigned short endport,
                      int proto, unsigned int * number)
{
	const struct lease_entry * row;
	unsigned short * ports;
	unsigned int n = 0;

	for(row = lease_table_next_port(NULL); row != NULL; row = lease_table_next_port(row)) {
		if(row->proto == proto && startport <= row->eport && row->eport <= endport)
			n++;
	}
	*number = 0;
	ports = calloc(n > 0 ? n : 1, sizeof(*ports));
	if(ports == NULL) {
		syslog(LOG_ERR, "memmap_ports_in_range: no memory for %u ports", n);
		return NULL;
	}
	for(row = lease_table_next_port(NULL); row != NULL; row = lease_table_next_port(row)) {
		if(row->proto == proto && startport <= row->eport && row->eport <= endport)
			ports[(*number)++] = row->eport;
	}
	syslog(LOG_DEBUG, "memmap: %u %s ports in %hu-%hu", *number, proto_itoa(proto),
	       startport, endport);
	return ports;
}

/* Tell if another internal address maps this external port. */
int
memmap_eport_used_by_other(unsigned short eport, const char * iaddr)
{
	struct in6_addr a;
	struct lease_entry * row;
	char other[INET_ADDRSTRLEN];
	if(v4_mapped(iaddr, &a) < 0)
		return 0;
	row = lease_table_port_used_by_other(AF_INET, NULL, eport, &a);
	if(row == NULL)
		return 0;
	if(inet_ntop(AF_INET, row->iaddr.s6_addr + 12, other, sizeof(other)) != NULL)
		syslog(LOG_INFO, "external port %hu is used by %s", eport, other);
	return 1;
}

/* Read the counters of an IPv4 port mapping from the firewall. */
int
memmap_map_counters(unsigned short eport, int proto,
                    u_int64_t * packets, u_int64_t * bytes)
{
	unsigned short iport;
	unsigned int timestamp;
	return get_redirect_rule(ext_if_name, eport, proto, NULL, 0, &iport, NULL, 0,
	                         NULL, 0, &timestamp, packets, bytes) >= 0 ? 0 : -1;
}

/* Give a row to each rule of an earlier run which has none. The row has the
 * lifetime the firewall reports, or 0 for none: then it does not expire. A rule
 * with a row is skipped, so a repeated call is safe. */
void
memmap_adopt_rules(void)
{
	int index = 0, proto;
	unsigned short eport, iport;
	char iaddr[32], desc[64], rhost[40];
	unsigned int timestamp;

	for(;;) {
		desc[0] = '\0';
		rhost[0] = '\0';
		timestamp = 0;
		if(get_redirect_rule_by_index(index++, NULL, &eport, iaddr, sizeof(iaddr),
		                              &iport, &proto, desc, sizeof(desc),
		                              rhost, sizeof(rhost), &timestamp, NULL, NULL) < 0)
			break;
		if(memmap_map_known(eport, proto))
			continue;
		syslog(LOG_NOTICE, "adopting rule %hu %s to %s:%hu", eport,
		       proto_itoa(proto), iaddr, iport);
		if(rhost[0] != '\0' && strcmp(rhost, "*") != 0)
			memmap_remote_peer(0, rhost, 0, eport, iaddr, iport, proto, desc, timestamp);
		else
			memmap_map(0, eport, iaddr, iport, proto, desc, timestamp);
	}
}

#ifdef ENABLE_UPNPPINHOLE
/* Find a pinhole by its rule, in the firewall. */
int
memmap_find_pinhole(const char * raddr, unsigned short rport,
                    const char * iaddr, unsigned short iport, int proto,
                    char * desc, int desclen, unsigned int * timestamp)
{
#ifdef MEMMAP_PINHOLES
	return find_pinhole(NULL, raddr, rport, iaddr, iport, proto,
	                    desc, desclen, timestamp);
#else
	UNUSED(raddr); UNUSED(rport); UNUSED(iaddr); UNUSED(iport); UNUSED(proto);
	UNUSED(desc); UNUSED(desclen); UNUSED(timestamp);
	return -42;
#endif
}

/* Read the rule of a pinhole from the firewall. */
int
memmap_get_pinhole(unsigned short uid, char * raddr, int raddrlen,
                   unsigned short * rport, char * iaddr, int iaddrlen,
                   unsigned short * iport, int * proto, char * desc, int desclen,
                   unsigned int * timestamp, u_int64_t * packets)
{
#ifdef MEMMAP_PINHOLES
	return get_pinhole_info(uid, raddr, raddrlen, rport, iaddr, iaddrlen, iport,
	                        proto, desc, desclen, timestamp, packets, NULL);
#else
	UNUSED(uid); UNUSED(raddr); UNUSED(raddrlen); UNUSED(rport);
	UNUSED(iaddr); UNUSED(iaddrlen); UNUSED(iport); UNUSED(proto);
	UNUSED(desc); UNUSED(desclen); UNUSED(timestamp); UNUSED(packets);
	return -42;
#endif
}

/* The uid of a pinhole by its place in the firewall. */
int
memmap_pinhole_uid_at(int index)
{
#if defined(USE_NETFILTER) && defined(MEMMAP_PINHOLES)
	return get_pinhole_uid_by_index(index);
#else
	UNUSED(index);
	return -42;
#endif
}

#ifdef MEMMAP_PINHOLES
/* keep the soonest expiry of a pinhole row */
static void
pinhole_next_row(struct lease_entry * e, void * arg)
{
	unsigned int * next = arg;
	unsigned int ts = (unsigned int)e->expiry;
	if(e->family == AF_INET6 && ts != 0 && (*next == 0 || ts < *next))
		*next = ts;
}

/* the sooner of two expiries, where 0 is none */
static unsigned int
sooner(unsigned int a, unsigned int b)
{
	if(a == 0)
		return b;
	if(b == 0)
		return a;
	return a < b ? a : b;
}
#endif

/* The firewall removes the expired pinholes: it holds their expiry. Reading
 * the rules costs a dump of the filter chain, so it happens only when a
 * pinhole is due: a row of the table, or a rule the last read found. A rule
 * of an earlier run has no row, and only the read finds its expiry. The
 * first call reads the rules. */
int
memmap_expire_pinholes(unsigned int * next)
{
#ifdef MEMMAP_PINHOLES
	static int rules_read;
	static unsigned int rules_next;	/* soonest expiry in the rules, 0 : none */
	unsigned int now = (unsigned int)upnp_time();
	unsigned int rows_next = 0, fw_next = 0;
	int removed;

	lease_table_foreach(pinhole_next_row, &rows_next);
	if(rules_read && (rows_next == 0 || rows_next > now) &&
	   (rules_next == 0 || rules_next > now)) {
		*next = sooner(rows_next, rules_next);
		return 0;
	}
	removed = clean_pinhole_list(&fw_next);
	memmap_remote_peers_expired(now, removed);
	if(removed < 0) {
		*next = now + 1;	/* read again soon */
		return removed;
	}
	rules_read = 1;
	rules_next = fw_next;
	*next = fw_next;
	return removed;
#else
	UNUSED(next);
	return 0;
#endif
}
#endif /* ENABLE_UPNPPINHOLE */

#ifdef PCP_PEER
/* Read a PEER rule from the firewall. */
int
memmap_get_peer_at(int index, unsigned short * eport, char * iaddr, int iaddrlen,
                   unsigned short * iport, int * proto, char * desc, int desclen,
                   char * rhost, int rhostlen, unsigned short * rport,
                   unsigned int * timestamp, u_int64_t * packets, u_int64_t * bytes)
{
	return get_peer_rule_by_index(index, NULL, eport, iaddr, iaddrlen, iport, proto,
	                              desc, desclen, rhost, rhostlen, rport, timestamp,
	                              packets, bytes) >= 0 ? 0 : -1;
}

/* Find the external address of a connection in the kernel. */
int
memmap_peer_nat_addr(struct sockaddr * intaddr, struct sockaddr * peer,
                     unsigned char proto, struct sockaddr * ext)
{
	return get_nat_ext_addr(intaddr, peer, proto, ext);
}
#endif /* PCP_PEER */
