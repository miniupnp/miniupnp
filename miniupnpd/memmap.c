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
#include "upnpredirect.h"
#include "lease_table.h"
#include "memmap.h"
#ifdef USE_NFTABLES
#include "netfilter_nft/nftnlrdr.h"
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
	e.family = AF_INET;
	e.proto = (unsigned char)proto;
	e.eport = eport;
	e.iport = iport;
	e.expiry = timestamp;
	e.label = (char *)desc;	/* copied */
	set_owner(&e, desc ? desc : "", eport, proto);
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
	set_owner(&e, desc ? desc : "", iport, proto);
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
	/* the firewall gives :: for a rule with no remote */
	int has_remote = raddr != NULL && raddr[0] != '\0' &&
	                 inet_pton(AF_INET6, raddr, &r) == 1 &&
	                 !IN6_IS_ADDR_UNSPECIFIED(&r);
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

void
memmap_remote_peers_partial(void)
{
	pinholes_partial = 1;
}

/* the firewall removed expired pinholes : they go by their lifetime here */
void
memmap_remote_peers_expired(unsigned int now, int removed)
{
	static struct pinhole_expiry c;
	unsigned int i;
	int partial = pinholes_partial;

	pinholes_partial = 0;
	if(removed <= 0 || partial)
		return;
	do {
		c.now = now;
		c.n = 0;
		lease_table_foreach(pinhole_expiry_row, &c);
		for(i = 0; i < c.n; i++)
			lease_table_remove(c.rows[i]);
	} while(c.n == PINHOLE_EXPIRE_MAX);
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
