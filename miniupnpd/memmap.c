/* The layer between the protocols and the mapping table. See memmap.h.
 *
 * memmap_sync() is the one write path of the protocols: it builds the rows of
 * a request out of the table, sends them to the firewall with fw_sync(), and
 * links them only if the firewall took them. A lookup never finds a row the
 * firewall refused.
 *
 * Functions this file gets later:
 * memmap_add_filter()	the third add: a FILTER peer on the row of a PCP MAP. */
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


static struct lease_entry * new_row(const struct memmap_change * c);

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
 * (<0 : error). The rows which expired go: a complete pass leaves no expired
 * rule, also when it removed none because the rules were already gone. If the
 * pass failed or was partial, the rows stay for the next pass: a row must not
 * go while its rule may still be there. */
static void
memmap_remote_peers_expired(unsigned int now, int removed)
{
	static struct pinhole_expiry c;
	unsigned int i, total = 0;
	int partial = pinholes_partial;

	pinholes_partial = 0;
	if(removed < 0 || partial) {
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

int
memmap_map_in_firewall(unsigned short eport, int proto)
{
	u_int64_t packets, bytes;
	struct lease_entry * row;

	if(memmap_map_counters(eport, proto, &packets, &bytes) == 0)
		return 1;
	syslog(LOG_INFO, "port %hu %s has no rule in the firewall, adding it again",
	       eport, proto_itoa(proto));
	/* the rule is gone already: only the row goes */
	row = lease_table_find_mapping(proto, AF_INET, NULL, eport);
	if(row != NULL)
		lease_table_remove(row);
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
	struct memmap_change c;
	struct lease_entry * row;

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
		memset(&c, 0, sizeof(c));
		c.raddr = rhost;
		c.eport = eport;
		c.iaddr = iaddr;
		c.iport = iport;
		c.proto = proto;
		c.desc = desc;
		c.timestamp = timestamp;
		row = new_row(&c);
		if(row != NULL)
			lease_table_link(row);
	}
}

#ifdef ENABLE_UPNPPINHOLE
/* Find a pinhole by its rule, in the firewall. */
int
memmap_find_pinhole(const char * raddr, unsigned short rport,
                    const char * iaddr, unsigned short iport, int proto,
                    char * desc, int desclen, unsigned int * timestamp)
{
#ifdef FW_PINHOLES
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
#ifdef FW_PINHOLES
	return get_pinhole_info(uid, raddr, raddrlen, rport, iaddr, iaddrlen, iport,
	                        proto, desc, desclen, timestamp, packets, NULL);
#else
	UNUSED(uid); UNUSED(raddr); UNUSED(raddrlen); UNUSED(rport);
	UNUSED(iaddr); UNUSED(iaddrlen); UNUSED(iport); UNUSED(proto);
	UNUSED(desc); UNUSED(desclen); UNUSED(timestamp); UNUSED(packets);
	return -42;
#endif
}

int
memmap_pinhole_has_row(unsigned short uid)
{
	return lease_table_find_uid(uid) != NULL;
}

/* The uid of a pinhole by its place in the firewall. */
int
memmap_pinhole_uid_at(int index)
{
#if defined(USE_NETFILTER) && defined(FW_PINHOLES)
	return get_pinhole_uid_by_index(index);
#else
	UNUSED(index);
	return -42;
#endif
}

#ifdef FW_PINHOLES
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
#ifdef FW_PINHOLES
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

#if defined(USE_NETFILTER) && !defined(USE_NFTABLES)
/* The chains of other programs, where a port forward of theirs can use a port. */
#ifdef TOMATO
static const char * const foreign_nat_chains[] = { "WANPREROUTING", NULL };
#else
static const char * const foreign_nat_chains[] = { "PREROUTING", NULL };
#endif
#endif

int
memmap_eport_redirected_elsewhere(const char * ifname, unsigned short eport, int proto,
                                  const char * iaddr, unsigned short iport)
{
	struct lease_entry * row = lease_table_find_mapping(proto, AF_INET, NULL, eport);
	char old[INET_ADDRSTRLEN];

	/* ours: the table */
	if(row != NULL && inet_ntop(AF_INET, row->iaddr.s6_addr + 12, old, sizeof(old)) != NULL &&
	   (strcmp(iaddr, old) != 0 || row->iport != iport)) {
		syslog(LOG_DEBUG, "port %hu %s is mapped to %s port %hu", eport,
		       proto_itoa(proto), old, row->iport);
		return 1;
	}
#if defined(USE_NETFILTER) && !defined(USE_NFTABLES)
	/* those of other programs: only the firewall has them */
	{
		unsigned short iport_old;
		int i;
		for(i = 0; foreign_nat_chains[i] != NULL; i++) {
			if(get_nat_redirect_rule(foreign_nat_chains[i], ifname, eport, proto,
			                         old, sizeof(old), &iport_old,
			                         NULL, 0, NULL, 0, NULL, NULL, NULL) == 0 &&
			   (strcmp(iaddr, old) != 0 || iport != iport_old)) {
				syslog(LOG_DEBUG, "port %hu %s is redirected to %s port %hu on chain %s",
				       eport, proto_itoa(proto), old, iport_old, foreign_nat_chains[i]);
				return 1;
			}
		}
	}
#else
	UNUSED(ifname);
#endif
	return 0;
}

/* Fill a row from the strings of a change. iaddr gives the family: an IPv6
 * row is a pinhole, with eaddr and eport those of the internal side. 0, or -1
 * if an address does not parse. */
static int
row_of(const struct memmap_change * c, struct lease_entry * e,
       struct in6_addr * raddr, int * has_remote)
{
	int v6 = strchr(c->iaddr, ':') != NULL;
	int any = c->raddr == NULL || c->raddr[0] == '\0' || strcmp(c->raddr, "*") == 0;

	memset(e, 0, sizeof(*e));
	if(v6) {
		if(inet_pton(AF_INET6, c->iaddr, &e->iaddr) != 1)
			return -1;
		e->eaddr = e->iaddr;
		e->family = AF_INET6;
		e->eport = c->iport;
		/* the firewall gives :: for a rule with no remote */
		*has_remote = !any && inet_pton(AF_INET6, c->raddr, raddr) == 1 &&
		              !IN6_IS_ADDR_UNSPECIFIED(raddr);
	} else {
		if(v4_mapped(c->iaddr, &e->iaddr) < 0)
			return -1;
		e->family = AF_INET;
		e->eport = c->eport;
		*has_remote = !any && v4_mapped(c->raddr, raddr) == 0;
	}
	e->proto = (unsigned char)c->proto;
	e->iport = c->iport;
	e->expiry = c->timestamp;
	e->label = (char *)c->desc;	/* lease_table_new() copies it */
	set_owner(e, c->desc ? c->desc : "", e->eport, c->proto);
	if(v6 && e->kind == LEASE_UPNP)
		lease_set_uid(e, (unsigned short)c->uid);
	return 0;
}

/* A new row for a change, not linked. NULL if it has a wrong address or there
 * is no memory. */
static struct lease_entry *
new_row(const struct memmap_change * c)
{
	struct lease_entry e;
	struct in6_addr raddr;
	int has_remote;
	if(c->iaddr == NULL || row_of(c, &e, &raddr, &has_remote) < 0)
		return NULL;
	return lease_table_new(&e, has_remote ? &raddr : NULL, c->rport);
}

/* The linked row with the external key of a row, whatever its remote for an
 * IPv4 port mapping, which owns its port alone. */
static struct lease_entry *
row_at_key(const struct lease_entry * e)
{
	if(e->family == AF_INET)
		return lease_table_find_mapping(e->proto, AF_INET, NULL, e->eport);
	return lease_table_find_external(e->proto, AF_INET6, &e->eaddr, e->eport,
	                                 e->remote ? &e->remote->raddr : NULL,
	                                 e->remote ? e->remote->rport : 0);
}

/* 1 if two rows stand for one rule of one owner: a renewal then keeps the
 * linked row and its place on the port list. */
static int
same_rule(const struct lease_entry * a, const struct lease_entry * b)
{
	if(a->family != b->family || a->proto != b->proto || a->eport != b->eport ||
	   a->iport != b->iport || memcmp(&a->iaddr, &b->iaddr, sizeof(a->iaddr)) != 0 ||
	   !lease_table_same_owner(a, b))
		return 0;
	if(a->remote == NULL || b->remote == NULL)
		return a->remote == b->remote;
	return a->remote->rport == b->remote->rport &&
	       memcmp(&a->remote->raddr, &b->remote->raddr, sizeof(a->remote->raddr)) == 0;
}

/* One change of a request, between memmap_sync() and fw_sync() */
struct stage {
	struct lease_entry * row;	/* the new row, not linked, or NULL */
	struct lease_entry * old;	/* the linked row which goes or is renewed */
	struct lease_entry rule;	/* the rule of a delete or renewal with no row */
};

/* Build the rows of a change, and the change for fw_sync(). 0, or -1 if a
 * row cannot be built: then nothing is sent. */
static int
stage_change(struct memmap_change * c, struct stage * st, struct fw_change * fw)
{
	int pinhole = c->iaddr != NULL && strchr(c->iaddr, ':') != NULL;

	memset(st, 0, sizeof(*st));
	memset(fw, 0, sizeof(*fw));
	switch(c->op) {
	case MEMMAP_ADD:
		/* the firewall gives the uid of a new pinhole */
		if(pinhole)
			c->uid = 0;
		st->row = new_row(c);
		if(st->row == NULL)
			return -1;
		st->old = row_at_key(st->row);
		fw->op = FW_ADD;
		break;
	case MEMMAP_UPDATE:
	case MEMMAP_RENEW:
		if(c->op == MEMMAP_RENEW)
			st->old = lease_table_find_uid((unsigned short)c->uid);
		if(c->iaddr != NULL) {
			st->row = new_row(c);
		} else if(st->old != NULL) {
			/* a renewal by uid: the rule stays, with a new expiry */
			struct lease_entry e = *st->old;
			e.expiry = c->timestamp;
			st->row = lease_table_new(&e, st->old->remote ? &st->old->remote->raddr : NULL,
			                          st->old->remote ? st->old->remote->rport : 0);
		}
		if(st->row == NULL)
			return -1;
		if(st->old == NULL)
			st->old = row_at_key(st->row);
		if(st->old == NULL) {
			/* a rule of an earlier run, which has no row yet */
			st->rule = *st->row;
			st->rule.iport = 0;	/* an update then rewrites the whole rule */
		}
		fw->op = FW_UPDATE;
		break;
	case MEMMAP_DELETE:
		st->old = lease_table_find_mapping(c->proto, AF_INET, NULL, c->eport);
		st->rule.family = AF_INET;
		st->rule.proto = (unsigned char)c->proto;
		st->rule.eport = c->eport;
		fw->op = FW_DELETE;
		break;
	case MEMMAP_DELETE_PINHOLE:
		st->old = lease_table_find_uid((unsigned short)c->uid);
		if(st->old == NULL && c->iaddr != NULL) {
			/* a PCP pinhole has no uid in the table : its row is by its rule */
			struct lease_entry * e = new_row(c);
			if(e != NULL) {
				st->old = row_at_key(e);
				lease_table_free(e);
			}
		}
		st->rule.family = AF_INET6;
		fw->op = FW_DELETE;
		break;
	}
	fw->row = st->row;
	fw->old = st->old != NULL ? st->old : &st->rule;
	fw->old_partial = st->old == NULL;
	fw->uid = (unsigned short)(c->uid > 0 ? c->uid : 0);
	return 0;
}

/* The firewall has the change: put its rows in the table. */
static void
apply_change(const struct memmap_change * c, struct stage * st)
{
	switch(c->op) {
	case MEMMAP_ADD:
	case MEMMAP_UPDATE:
	case MEMMAP_RENEW:
		if(c->op != MEMMAP_ADD && st->old != NULL && same_rule(st->old, st->row)) {
			/* a renewal: the row stays, and keeps its place on the list */
			char * label = st->old->label;
			st->old->expiry = st->row->expiry;
			st->old->label = st->row->label;
			st->row->label = label;
			lease_table_free(st->row);
			syslog(LOG_DEBUG, "memmap: renew %s port %hu, expiry %u",
			       proto_itoa(st->old->proto), st->old->eport,
			       (unsigned int)st->old->expiry);
		} else {
			if(st->old != NULL) {
				syslog(LOG_DEBUG, "memmap: replace the row of %s port %hu",
				       proto_itoa(st->old->proto), st->old->eport);
				lease_table_remove(st->old);
			}
			lease_table_link(st->row);
			syslog(LOG_INFO, "memmap: add %s %s port %hu, uid %hu, remote %s, expiry %u",
			       st->row->family == AF_INET6 ? "pinhole" : "mapping",
			       proto_itoa(st->row->proto), st->row->eport, lease_uid(st->row),
			       st->row->remote ? "set" : "any", (unsigned int)st->row->expiry);
		}
		break;
	case MEMMAP_DELETE:
	case MEMMAP_DELETE_PINHOLE:
		if(st->old != NULL) {
			syslog(LOG_INFO, "memmap: remove %s %s port %hu",
			       st->old->family == AF_INET6 ? "pinhole" : "mapping",
			       proto_itoa(st->old->proto), st->old->eport);
			lease_table_remove(st->old);
		}
		break;
	}
	st->row = NULL;
	st->old = NULL;
}

/* The firewall does not have the change: free what was built for it. */
static void
discard_change(const struct memmap_change * c, struct stage * st)
{
	(void)c;
	lease_table_free(st->row);
	st->row = NULL;
}

/* 1 if change i goes to a row which a change before it in the request goes
 * to: the first would free the row the second uses. */
static int
shares_row(const struct stage * st, int i)
{
	int j;
	if(st[i].old == NULL)
		return 0;
	for(j = 0; j < i; j++) {
		if(st[j].old == st[i].old) {
			syslog(LOG_WARNING, "memmap_sync: changes %d and %d go to one row", j + 1, i + 1);
			return 1;
		}
	}
	return 0;
}

/* Stage the rows of a request, send it, and link or free the rows. */
int
memmap_sync(struct memmap_change * changes, int n)
{
	struct stage * st;
	struct fw_change * fw;
	int i, r;

	if(n <= 0)
		return 0;
	st = calloc(n, sizeof(*st));
	fw = calloc(n, sizeof(*fw));
	if(st == NULL || fw == NULL) {
		syslog(LOG_ERR, "memmap_sync: no memory for %d changes", n);
		free(st);
		free(fw);
		return -1;
	}
	for(i = 0; i < n; i++) {
		if(stage_change(&changes[i], &st[i], &fw[i]) < 0)
			break;
		if(shares_row(st, i))
			break;
	}
	if(i < n) {
		syslog(LOG_WARNING, "memmap_sync: cannot build change %d of %d", i + 1, n);
		discard_change(&changes[i], &st[i]);
		while(i-- > 0)
			discard_change(&changes[i], &st[i]);
		free(st);
		free(fw);
		return -1;
	}
	r = fw_sync(fw, n);
	for(i = 0; i < n; i++) {
		/* the firewall chose the uid of a new pinhole: its row takes it */
		if(changes[i].op == MEMMAP_ADD && st[i].row != NULL &&
		   st[i].row->family == AF_INET6) {
			changes[i].uid = fw[i].uid;
			if(st[i].row->kind == LEASE_UPNP)
				lease_set_uid(st[i].row, fw[i].uid);
		}
		if(r == 0 || fw[i].applied == FW_APPLIED) {
			apply_change(&changes[i], &st[i]);
		} else if(fw[i].applied == FW_HALF_APPLIED) {
			/* a part of the rules stayed: the expiry tries the delete again */
			unsigned int now = (unsigned int)upnp_time();
			st[i].row->expiry = now;
			apply_change(&changes[i], &st[i]);
			nextruletoclean_timestamp = now;
		} else {
			discard_change(&changes[i], &st[i]);
		}
	}
	free(st);
	free(fw);
	return r;
}
