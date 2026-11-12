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
#define MEMMAP_MAP6
#if defined(USE_NETFILTER)
#include "netfilter/iptpinhole.h"
#else
#include "pf/pfpinhole.h"
#endif
#endif
#endif


/* memmap_pton(), memmap_ntop(), memmap_key_init(): shared with memmap_stub.c */
#include "memmap_key.c"

/* The table form of an IPv4 address. 0, or -1 if s is not an IPv4 address */
static int
v4_mapped(const char * s, struct in6_addr * a)
{
	int family;
	return memmap_pton(s, &family, a) == 0 && family == AF_INET ? 0 : -1;
}

void
memmap_owner_init(struct memmap_owner * o, int kind, const void * nonce)
{
	memset(o, 0, sizeof(*o));
	o->kind = (unsigned char)kind;
	if(nonce != NULL)
		memcpy(o->nonce, nonce, sizeof(o->nonce));
}

/* the value of a hex digit. mapping_owner_of() has checked the digits */
static int
hex_value(int c)
{
	if(c >= '0' && c <= '9') return c - '0';
	if(c >= 'a' && c <= 'f') return c - 'a' + 10;
	return c - 'A' + 10;
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

/* The owner a description names: a PCP description ends in the 24 hex
 * digits of the nonce. See mapping_owner_of(). */
void
memmap_owner_from_desc(const char * desc, unsigned short eport, int proto,
                       struct memmap_owner * o)
{
	int owner = mapping_owner_of(desc != NULL ? desc : "", eport, proto);
	uint32_t w;
	int i, j;

	memmap_owner_init(o, owner_kind(owner), NULL);
	if(owner == MAPPING_PCP) {
		desc += strlen(desc) - 24;
		/* pcpserver.c copies the nonce off the wire into three uint32_t
		 * and prints each with %08x: a group of 8 digits is a word in
		 * host order. Copying the words back gives the bytes of the
		 * wire, the same as pcp_info_t.nonce holds. */
		for(i = 0; i < LEASE_NONCE_LEN / 4; i++) {
			w = 0;
			for(j = 0; j < 8; j++)
				w = w << 4 | (uint32_t)hex_value(*desc++);
			memcpy(o->nonce + 4 * i, &w, 4);
		}
	}
}

/* Give the row the owner of a request. A UPnP pinhole keeps its uid in the
 * nonce bytes. */
static void
set_owner(struct lease_entry * e, const struct memmap_owner * owner)
{
	unsigned short uid = lease_uid(e);
	e->kind = owner->kind;
	memcpy(e->nonce, owner->nonce, sizeof(e->nonce));
	if(e->family == AF_INET6 && e->kind == LEASE_UPNP)
		lease_set_uid(e, uid);
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
	struct memmap_owner owner;
	int has_remote = remote != NULL && v4_mapped(remote, &raddr) == 0;

	memset(&e, 0, sizeof(e));
	if(v4_mapped(iaddr, &e.iaddr) < 0)
		return;
	memmap_owner_from_desc(desc, eport, proto, &owner);
	set_owner(&e, &owner);
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

/* 1 if owner is the owner of the row. A UPnP row keeps its uid in the nonce
 * bytes, and a UPnP or NAT-PMP owner has no nonce: the kind is enough. */
static int
owned_by(const struct lease_entry * row, const struct memmap_owner * owner)
{
	if(row->kind != owner->kind)
		return 0;
	if(row->kind != LEASE_PCP_MAP)
		return 1;
	return memcmp(row->nonce, owner->nonce, LEASE_NONCE_LEN) == 0;
}

/* Find the first mapping of an internal endpoint. */
int
memmap_find(int family, const struct in6_addr * iaddr, unsigned short iport,
            int proto, const struct memmap_owner * owner, unsigned short * eport,
            char * desc, int desclen, unsigned int * timestamp)
{
	const struct lease_entry * row;
	char s[INET6_ADDRSTRLEN];

	for(row = lease_table_next_internal(NULL, proto, family, iaddr, iport); row != NULL;
	    row = lease_table_next_internal(row, proto, family, iaddr, iport)) {
		if(owner != NULL && !owned_by(row, owner))
			continue;
		*eport = row->eport;
		if(desc != NULL && desclen > 0)
			snprintf(desc, desclen, "%s", row->label ? row->label : "");
		if(timestamp != NULL)
			*timestamp = (unsigned int)row->expiry;
		syslog(LOG_DEBUG, "memmap: %s %s:%hu has external port %hu", proto_itoa(proto),
		       memmap_ntop(family, iaddr, s, sizeof(s)) ? s : "?", iport, row->eport);
		return 0;
	}
	syslog(LOG_DEBUG, "memmap: no mapping of %s %s:%hu", proto_itoa(proto),
	       memmap_ntop(family, iaddr, s, sizeof(s)) ? s : "?", iport);
	return -1;
}

/* Return the expiry of an IPv4 mapping. */
unsigned int
memmap_map_expiry(unsigned short eport, int proto)
{
	struct lease_entry * row = lease_table_find_mapping(proto, AF_INET, NULL, eport);
	return row != NULL ? (unsigned int)row->expiry : 0;
}

/* The remote of a pinhole as the key of its row: an address, or :: with a
 * port for a remote port with any remote host. 1 and *r, or 0 for none. NULL,
 * empty, "*" and :: are any remote host. */
static int
map6_remote(const char * raddr, unsigned short rport, struct in6_addr * r)
{
	if(raddr != NULL && raddr[0] != '\0' && inet_pton(AF_INET6, raddr, r) == 1 &&
	   !IN6_IS_ADDR_UNSPECIFIED(r))
		return 1;
	memset(r, 0, sizeof(*r));
	return rport != 0;
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
	struct memmap_owner owner;
	int has_remote;

	if(row != NULL && desc == NULL) {
		row->expiry = timestamp;
		return;
	}
	if(iaddr == NULL || inet_pton(AF_INET6, iaddr, &i) != 1)
		return;
	has_remote = map6_remote(raddr, rport, &r);
	/* PCP has no uid : the row of this rule is by its key */
	if(row == NULL)
		row = lease_table_find_external(proto, AF_INET6, &i, iport,
		                                has_remote ? &r : NULL, rport);
	if(row != NULL) {
		/* a renewal : the row stays. A UPnP row found by its key keeps
		 * it only with the same uid, or the uid index would be wrong */
		if(desc != NULL && row->label != NULL && strcmp(desc, row->label) == 0 &&
		   row->iport == iport && memcmp(&row->iaddr, &i, sizeof(i)) == 0 &&
		   (row->kind != LEASE_UPNP || lease_uid(row) == uid)) {
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
	memmap_owner_from_desc(desc, iport, proto, &owner);
	set_owner(&e, &owner);
	if(e.kind == LEASE_UPNP)
		lease_set_uid(&e, uid);
	/* if the row cannot be replaced, it stays: the rule is still there */
	if(row != NULL)
		row = lease_table_replace(row, &e, has_remote ? &r : NULL, rport);
	else
		row = lease_table_add(&e, has_remote ? &r : NULL, rport);
	if(row == NULL)
		syslog(LOG_WARNING, "lease table: could not add the row of pinhole %hu", uid);
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
	/* the firewall gives :: for a rule with no remote host */
	int has_remote = map6_remote(raddr, rport, &r);
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
#define MAP6_EXPIRE_MAX	256

/* what a walk over the rows gives pinhole_expiry_row() and gets back */
struct map6_expiry {
	time_t now;
	unsigned int n;
	struct lease_entry * rows[MAP6_EXPIRE_MAX];
};

/* collect the row if it is a pinhole past its expiry */
static void
map6_expiry_row(struct lease_entry * e, void * arg)
{
	struct map6_expiry * c = arg;
	if(e->family == AF_INET6 && e->expiry != 0 && e->expiry <= c->now &&
	   c->n < MAP6_EXPIRE_MAX)
		c->rows[c->n++] = e;
}

/* set by memmap_remote_peers_partial(), read and cleared by memmap_remote_peers_expired() */
static int map6_partial;

/* Keep the rows of the next pass over the pinholes. */
void
memmap_remote_peers_partial(void)
{
	map6_partial = 1;
	syslog(LOG_DEBUG, "memmap: expired pinhole rules are left in the firewall");
}

/* The firewall ended a pass over the pinholes, and removed "removed" rules
 * (<0 : error). The rows which expired go, as their rules went. If the pass
 * removed nothing, failed or was partial, the rows stay for the next pass: a row
 * must not go while its rule may still be there. */
static void
memmap_remote_peers_expired(unsigned int now, int removed)
{
	static struct map6_expiry c;
	unsigned int i, total = 0;
	int partial = map6_partial;

	map6_partial = 0;
	if(removed <= 0 || partial) {
		if(removed != 0 || partial)
			syslog(LOG_DEBUG, "memmap: keep the expired pinhole rows, removed %d, partial %d",
			       removed, partial);
		return;
	}
	do {
		c.now = now;
		c.n = 0;
		lease_table_foreach(map6_expiry_row, &c);
		for(i = 0; i < c.n; i++)
			lease_table_remove(c.rows[i]);
		total += c.n;
	} while(c.n == MAP6_EXPIRE_MAX);
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

/* Copy a row of a mapping out, for memmap_get() and memmap_get_at(). NULL for
 * what is not wanted. */
static void
port_info(const struct lease_entry * row, unsigned short * iport,
          struct in6_addr * iaddr, char * desc, int desclen,
          struct memmap_remote * remote, unsigned int * timestamp)
{
	if(iport != NULL)
		*iport = row->iport;
	if(iaddr != NULL)
		*iaddr = row->iaddr;
	if(desc != NULL && desclen > 0)
		snprintf(desc, desclen, "%s", row->label ? row->label : "");
	if(remote != NULL) {
		memset(remote, 0, sizeof(*remote));
		if(row->remote != NULL) {
			remote->raddr = row->remote->raddr;
			remote->rport = row->remote->rport;
		}
	}
	if(timestamp != NULL)
		*timestamp = (unsigned int)row->expiry;
}

/* Read a mapping by its external port. */
int
memmap_get(int family, const struct in6_addr * eaddr, unsigned short eport,
           int proto, unsigned short * iport, struct in6_addr * iaddr,
           char * desc, int desclen, struct memmap_remote * remote,
           unsigned int * timestamp)
{
	const struct lease_entry * row = lease_table_find_mapping(proto, family, eaddr, eport);
	if(row == NULL) {
		syslog(LOG_DEBUG, "memmap: no mapping of %s port %hu", proto_itoa(proto), eport);
		return -1;
	}
	port_info(row, iport, iaddr, desc, desclen, remote, timestamp);
	syslog(LOG_DEBUG, "memmap: read %s port %hu", proto_itoa(proto), eport);
	return 0;
}

/* The kind of the row of an IPv4 port mapping. */
int
memmap_map_kind(unsigned short eport, int proto)
{
	const struct lease_entry * row = lease_table_find_mapping(proto, AF_INET, NULL, eport);
	return row != NULL ? row->kind : -1;
}

/* Read an IPv4 mapping by its place on the port list. */
int
memmap_get_at(unsigned int index, unsigned short * eport, int * proto,
              unsigned short * iport, struct in6_addr * iaddr,
              char * desc, int desclen, struct memmap_remote * remote,
              unsigned int * timestamp)
{
	const struct lease_entry * row = lease_table_port_at(index);
	if(row == NULL) {
		syslog(LOG_DEBUG, "memmap: no mapping at index %u", index);
		return -1;
	}
	*eport = row->eport;
	*proto = row->proto;
	port_info(row, iport, iaddr, desc, desclen, remote, timestamp);
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
	/* no more ports than the range holds, nor than are mapped: one walk */
	unsigned int n = lease_table_port_count();

	if(endport >= startport && (unsigned int)(endport - startport) + 1 < n)
		n = (unsigned int)(endport - startport) + 1;
	*number = 0;
	ports = calloc(n > 0 ? n : 1, sizeof(*ports));
	if(ports == NULL) {
		syslog(LOG_ERR, "memmap_ports_in_range: no memory for %u ports", n);
		return NULL;
	}
	for(row = lease_table_next_port(NULL); row != NULL && *number < n;
	    row = lease_table_next_port(row)) {
		if(row->proto == proto && startport <= row->eport && row->eport <= endport)
			ports[(*number)++] = row->eport;
	}
	syslog(LOG_DEBUG, "memmap: %u %s ports in %hu-%hu", *number, proto_itoa(proto),
	       startport, endport);
	return ports;
}

/* Tell if another internal address maps this external port. */
int
memmap_eport_used_by_other(int family, const struct in6_addr * eaddr,
                           unsigned short eport, const struct in6_addr * iaddr)
{
	struct lease_entry * row;
	char other[INET6_ADDRSTRLEN];

	row = lease_table_port_used_by_other(family, eaddr, eport, iaddr);
	if(row == NULL)
		return 0;
	if(memmap_ntop(row->family, &row->iaddr, other, sizeof(other)) != NULL)
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

int
memmap_in_firewall(const struct memmap_key * key)
{
	u_int64_t packets, bytes;

	if(memmap_map_counters(key->eport, key->proto, &packets, &bytes) == 0)
		return 1;
	syslog(LOG_INFO, "port %hu %s has no rule in the firewall, adding it again",
	       key->eport, proto_itoa(key->proto));
	memmap_map_gone(key->eport, key->proto);
	return 0;
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
		/* a backend may fill a long description with no terminator */
		desc[sizeof(desc) - 1] = '\0';
		rhost[sizeof(rhost) - 1] = '\0';
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
memmap_find_map6(const char * raddr, unsigned short rport,
                    const char * iaddr, unsigned short iport, int proto,
                    char * desc, int desclen, unsigned int * timestamp)
{
#ifdef MEMMAP_MAP6
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
memmap_get_map6(unsigned short uid, char * raddr, int raddrlen,
                   unsigned short * rport, char * iaddr, int iaddrlen,
                   unsigned short * iport, int * proto, char * desc, int desclen,
                   unsigned int * timestamp, u_int64_t * packets)
{
#ifdef MEMMAP_MAP6
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
memmap_map6_uid_at(int index)
{
#if defined(USE_NETFILTER) && defined(MEMMAP_MAP6)
	return get_pinhole_uid_by_index(index);
#else
	UNUSED(index);
	return -42;
#endif
}

/* The firewall removes the expired pinholes: it holds their expiry. */
int
memmap_expire_map6(unsigned int * next)
{
#ifdef MEMMAP_MAP6
	int removed = clean_pinhole_list(next);
	memmap_remote_peers_expired((unsigned int)upnp_time(), removed);
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

#if defined(USE_NETFILTER) && !defined(USE_NFTABLES)
/* The chains of other programs, where a port forward of theirs can use a port. */
#ifdef TOMATO
static const char * const foreign_nat_chains[] = { "WANPREROUTING", NULL };
#else
static const char * const foreign_nat_chains[] = { "PREROUTING", NULL };
#endif
#endif

int
memmap_eport_redirected_elsewhere(const char * ifname, const struct memmap_key * key)
{
	struct lease_entry * row = lease_table_find_mapping(key->proto, key->family,
	                                                    &key->eaddr, key->eport);
	char old[INET6_ADDRSTRLEN];

	/* ours: the table */
	if(row != NULL &&
	   (memcmp(&row->iaddr, &key->iaddr, sizeof(row->iaddr)) != 0 ||
	    row->iport != key->iport)) {
		syslog(LOG_DEBUG, "port %hu %s is mapped to %s port %hu", key->eport,
		       proto_itoa(key->proto),
		       memmap_ntop(row->family, &row->iaddr, old, sizeof(old)) ? old : "?",
		       row->iport);
		return 1;
	}
#if defined(USE_NETFILTER) && !defined(USE_NFTABLES)
	/* those of other programs: only the firewall has them */
	{
		char iaddr[INET6_ADDRSTRLEN];
		unsigned short iport_old;
		int i;
		if(memmap_ntop(key->family, &key->iaddr, iaddr, sizeof(iaddr)) == NULL)
			return 0;
		for(i = 0; foreign_nat_chains[i] != NULL; i++) {
			if(get_nat_redirect_rule(foreign_nat_chains[i], ifname, key->eport, key->proto,
			                         old, sizeof(old), &iport_old,
			                         NULL, 0, NULL, 0, NULL, NULL, NULL) == 0 &&
			   (strcmp(iaddr, old) != 0 || key->iport != iport_old)) {
				syslog(LOG_DEBUG, "port %hu %s is redirected to %s port %hu on chain %s",
				       key->eport, proto_itoa(key->proto), old, iport_old,
				       foreign_nat_chains[i]);
				return 1;
			}
		}
	}
#else
	UNUSED(ifname);
#endif
	return 0;
}
