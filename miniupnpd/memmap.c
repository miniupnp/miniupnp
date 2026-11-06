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
#include "upnputils.h"
#include "lease_table.h"
#include "memmap.h"
#ifdef USE_NFTABLES
#include "netfilter_nft/nftnlrdr.h"
#endif

/* The table keeps every address in 16 bytes: a.b.c.d as ::ffff:a.b.c.d. */
int
memmap_pton(const char * s, int * family, struct in6_addr * a)
{
	struct in_addr v4;

	if(s == NULL)
		return -1;
	if(inet_pton(AF_INET, s, &v4) == 1) {
		memset(a, 0, sizeof(*a));
		a->s6_addr[10] = a->s6_addr[11] = 0xff;
		memcpy(a->s6_addr + 12, &v4, sizeof(v4));
		*family = AF_INET;
		return 0;
	}
	if(inet_pton(AF_INET6, s, a) == 1) {
		*family = AF_INET6;
		return 0;
	}
	return -1;
}

/* Print an address of the table. */
const char *
memmap_ntop(int family, const struct in6_addr * a, char * buf, size_t len)
{
	if(family == AF_INET)
		return inet_ntop(AF_INET, a->s6_addr + 12, buf, len);
	return inet_ntop(AF_INET6, a, buf, len);
}

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
		return;
	}
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
}

/* Remove the row of an IPv4 mapping: the one row of its port. */
void
memmap_map_gone(unsigned short eport, int proto)
{
	struct lease_entry * row = lease_table_find_mapping(proto, AF_INET, NULL, eport);
	if(row != NULL)
		lease_table_remove(row);
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
		return 0;
	}
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
			return;
		}
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
		syslog(LOG_WARNING, "lease table: could not add Remote peer %hu", uid);
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
	if(row != NULL)
		row->expiry = timestamp;
}

/* Remove the row of a pinhole by its uid. */
void
memmap_remote_peer_gone(unsigned short uid)
{
	struct lease_entry * row = lease_table_find_uid(uid);
	if(row != NULL)
		lease_table_remove(row);
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
		return;
	}
	if(inet_pton(AF_INET6, iaddr, &a) != 1)
		return;
	row = lease_table_find_external(proto, AF_INET6, &a, iport,
	                                has_remote ? &r : NULL, rport);
	if(row != NULL)
		lease_table_remove(row);
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
}

/* the firewall removed expired pinholes : they go by their lifetime here */
void
memmap_remote_peers_expired(unsigned int now, int removed)
{
	static struct map6_expiry c;
	unsigned int i;
	int partial = map6_partial;

	map6_partial = 0;
	if(removed <= 0 || partial)
		return;
	do {
		c.now = now;
		c.n = 0;
		lease_table_foreach(map6_expiry_row, &c);
		for(i = 0; i < c.n; i++)
			lease_table_remove(c.rows[i]);
	} while(c.n == MAP6_EXPIRE_MAX);
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

/* The nftables backend asks this which port mappings expired, with no read of
 * the firewall. Fills expired[] with at most max mappings, and returns how many.
 * *next is the time of the next expiry, 0 if there is none. */
int
get_expired_redirect_rules(unsigned int now, struct expired_redirect * expired,
                           int max, unsigned int * next)
{
	struct expiry_ctx c = { now, expired, max, 0, 0 };
	lease_table_foreach(expiry_row, &c);
	*next = c.next;
	return c.n;
}
#endif /* USE_NFTABLES */

/* Tell if an IPv4 mapping has a row. */
int
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
	if(row == NULL)
		return -1;
	port_info(row, iport, iaddr, iaddrlen, desc, desclen, rhost, rhostlen, timestamp);
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
	if(row == NULL)
		return -1;
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
