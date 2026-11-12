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
	e.family = AF_INET;
	e.proto = (unsigned char)proto;
	e.eport = eport;
	e.iport = iport;
	e.expiry = timestamp;
	e.label = (char *)desc;	/* copied */
	memmap_owner_from_desc(desc, eport, proto, &owner);
	set_owner(&e, &owner);
	/* a row on the port is replaced. If that fails, it stays: the port is
	 * still mapped */
	old = lease_table_find_mapping(proto, AF_INET, NULL, eport);
	if(old != NULL)
		row = lease_table_replace(old, &e, has_remote ? &raddr : NULL, rport);
	else
		row = lease_table_add(&e, has_remote ? &raddr : NULL, rport);
	if(row == NULL)
		syslog(LOG_WARNING, "lease table: could not add %hu %d", eport, proto);
}

void
memmap_map_gone(unsigned short eport, int proto)
{
	struct lease_entry * row = lease_table_find_mapping(proto, AF_INET, NULL, eport);
	if(row != NULL)
		lease_table_remove(row);
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
		syslog(LOG_WARNING, "lease table: could not add pinhole %hu", uid);
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

void
memmap_remote_peer_gone(unsigned short uid)
{
	struct lease_entry * row = lease_table_find_uid(uid);
	if(row != NULL)
		lease_table_remove(row);
}

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

/* Ask the firewall about the rule of an expired row. The row goes if it has
 * no rule. A rule which is still there keeps its row, with the expiry of the
 * rule: its removal failed, or it was renewed later than the row. */
static void
map6_expiry_check(struct lease_entry * e, memmap_map6_lookup lookup)
{
	char iaddr[INET6_ADDRSTRLEN], raddr[INET6_ADDRSTRLEN];
	unsigned int timestamp = 0;
	int remote_addr = e->remote != NULL && !IN6_IS_ADDR_UNSPECIFIED(&e->remote->raddr);
	int r;

	if(inet_ntop(AF_INET6, &e->iaddr, iaddr, sizeof(iaddr)) == NULL)
		return;
	if(remote_addr &&
	   inet_ntop(AF_INET6, &e->remote->raddr, raddr, sizeof(raddr)) == NULL)
		return;
	/* a remote port with any remote host is :: and the port */
	r = lookup(remote_addr ? raddr : NULL, e->remote ? e->remote->rport : 0,
	           iaddr, e->iport, e->proto, &timestamp);
	if(r == 0)
		e->expiry = timestamp;
	else if(r < 0)
		lease_table_remove(e);
	/* else the firewall could not be read: the row stays, for the next pass */
}

/* what a walk over the rows gives map6_expiry_row() */
struct map6_expiry {
	time_t now;
	memmap_map6_lookup lookup;
};

/* check the row if it is a pinhole past its expiry */
static void
map6_expiry_row(struct lease_entry * e, void * arg)
{
	const struct map6_expiry * c = arg;
	if(e->family == AF_INET6 && e->expiry != 0 && e->expiry <= c->now)
		map6_expiry_check(e, c->lookup);
}

void
memmap_remote_peers_expired(unsigned int now, memmap_map6_lookup lookup)
{
	struct map6_expiry c;

	c.now = now;
	c.lookup = lookup;
	lease_table_foreach(map6_expiry_row, &c);
}
