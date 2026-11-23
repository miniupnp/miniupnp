/* MiniUPnP project
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

/* A mapping as a protocol asks for it, in one shape for UPnP, NAT-PMP and
 * PCP. A protocol fills one lease_entry from its own message, and the
 * redirect and pinhole functions take a pointer to it. Nothing is copied
 * on the way down: the filters stay in the caller's array.
 *
 * Addresses are struct in6_addr, IPv4 as ::ffff:a.b.c.d. A request names
 * its protocol (kind) and, for PCP, its nonce. The description of the
 * firewall rule is no part of it.
 *
 * A PCP PEER is outgoing, an SNAT rule, and has a shape of its own:
 * struct outgoing_entry. */
#ifndef MAPREQ_H_INCLUDED
#define MAPREQ_H_INCLUDED

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "upnputils.h"

/* the protocol of a request. 0 is none of them: a request whose kind was
 * not set is no valid request. */
enum map_kind { MAP_KIND_PCP = 1, MAP_KIND_NATPMP, MAP_KIND_UPNP };

/* the size of a PCP mapping nonce (RFC 6887 section 11.1) */
#define MAP_NONCE_LEN	12

/* bits of lease_entry.flags */
#define MAP_PREFER_FAILURE	0x01	/* the suggested external port or none:
					 * PCP PREFER_FAILURE, UPnP AddPortMapping */

struct lease_entry;

/* One remote a mapping lets in. A mapping with no filter lets any remote
 * in. */
struct map_filter {
	struct in6_addr raddr;	/* IPv4 as ::ffff:a.b.c.d */
	unsigned char prefix;	/* the prefix length of raddr, on 128 bits
				 * also for IPv4. 0 : any host */
	unsigned short rport;	/* 0 : any port */
	unsigned short uid;	/* the UniqueID of a UPnP IPv6 rule, 0 : none.
				 * Set by upnp_add_inboundpinhole() */
	struct lease_entry * map;	/* the map of the filter in the lease
					 * table, NULL in a request */
};

/* A mapping: a request of a protocol, and the row of the lease table
 * (lease_table.h) once it is linked. A request on the stack leaves the
 * links of the table zero. */
struct lease_entry {
	/* the links of the lease table, see lease_table.h */
	struct lease_entry * ext_next;	/* the next row in its external bucket */
	struct lease_entry * int_next;	/* the next row in its internal bucket */
	/* The port list: the rows UPnP reads by position, which are the IPv4
	 * port mappings, oldest first. An IPv6 map is not on it. */
	struct lease_entry * port_next;
	struct lease_entry * port_prev;
	/* Names the row for its life: the lease files link their lines by
	 * it. lease_table_link() gives a row with 0 the next one. */
	unsigned long long id;
	unsigned int retry;	/* an expired row whose rules stay: the next try,
				 * on the clock of upnp_time(). 0 : none */
	int filters_alloc;	/* the room of filters, in a row of the table */
	unsigned char row;	/* made by lease_table_new(): the table may link
				 * it. 0 : a request on the stack */
	unsigned char linked;	/* in the indexes of the lease table */
	unsigned char fw_partial;	/* a failed change left a part of its rules:
					 * not renewed as it is */
	/* the mapping. The small fields first, then the addresses, so the row
	 * has no holes. */
	unsigned char kind;	/* enum map_kind */
	unsigned char flags;	/* MAP_* bits */
	unsigned char family;	/* of the internal side: AF_INET, AF_INET6 */
	unsigned char proto;	/* IPPROTO_TCP, IPPROTO_UDP, IPPROTO_UDPLITE */
	unsigned char nonce[MAP_NONCE_LEN];	/* PCP, else zero */
	struct in6_addr iaddr;
	/* The external side. IPv4: the WAN address, :: for that of
	 * ext_if_name. IPv6 with no translation: iaddr and iport. eport is the
	 * port asked for, 0 : any, and the port used once it is mapped. */
	struct in6_addr eaddr;
	unsigned short iport;
	unsigned short eport;
	struct map_filter * filters;	/* the caller's array, or the row's
					 * own. NULL : any remote. A UPnP IPv6
					 * map: one filter per pinhole, which
					 * carries its uid, prefix 0 : any
					 * remote */
	int nfilters;
	unsigned int timestamp;	/* the expiry on the clock of upnp_time(),
				 * 0 : none */
	const char * label;	/* the text of the client: the UPnP description,
				 * the PCP DESCRIPTION option. NULL : none.
				 * The rule gets map_rule_desc() */
};

/* One remote of an outgoing binding, with its own expiry. */
struct outgoing_peer {
	struct in6_addr raddr;	/* the destination, one host. IPv4 as ::ffff:a.b.c.d */
	unsigned short rport;	/* the destination port, never 0 */
	unsigned int timestamp;	/* the expiry on the clock of upnp_time() */
};

/* An outgoing binding as a client asks for it, an SNAT rule (PCP PEER,
 * RFC 6887 section 12): traffic from iaddr:iport to its peers leaves with
 * the source eaddr:eport, and only the replies come back. Not a DNAT map:
 * no kind, no flags, no filters. */
struct outgoing_entry {
	unsigned char nonce[MAP_NONCE_LEN];	/* the PCP mapping nonce */
	int family;		/* of the internal side: AF_INET, AF_INET6 */
	int proto;		/* IPPROTO_TCP, IPPROTO_UDP, IPPROTO_UDPLITE */
	struct in6_addr iaddr;	/* the source inside. IPv4 as ::ffff:a.b.c.d */
	unsigned short iport;
	struct in6_addr eaddr;	/* the source outside, the WAN address */
	unsigned short eport;	/* asked for, 0 : any; the one used once added */
	const char * label;	/* NULL: the PCP DESCRIPTION option is not
				 * read yet */
	struct outgoing_peer * peers;	/* the caller's array, at least one */
	int npeers;
};

/* An empty request of a protocol. nonce NULL : zero. Not for a row of
 * lease_table_new(): it would lose the filter array of the row. */
static inline void
lease_entry_init(struct lease_entry * r, int kind, const void * nonce)
{
	memset(r, 0, sizeof(*r));
	r->kind = (unsigned char)kind;
	if(nonce != NULL)
		memcpy(r->nonce, nonce, MAP_NONCE_LEN);
}

/* a.b.c.d as ::ffff:a.b.c.d, the form of a request */
static inline void
map_addr_v4(struct in6_addr * a, const struct in_addr * v4)
{
	memset(a, 0, sizeof(*a));
	a->s6_addr[10] = a->s6_addr[11] = 0xff;
	memcpy(a->s6_addr + 12, v4, sizeof(*v4));
}

/* Turn the text of an address into the form of a request: a.b.c.d as
 * ::ffff:a.b.c.d with *family AF_INET, IPv6 as it is with AF_INET6. 0, or -1
 * if s is no address. */
static inline int
map_pton(const char * s, int * family, struct in6_addr * a)
{
	struct in_addr v4;

	if(s == NULL)
		return -1;
	if(inet_pton(AF_INET, s, &v4) == 1) {
		map_addr_v4(a, &v4);
		*family = AF_INET;
		return 0;
	}
	if(inet_pton(AF_INET6, s, a) == 1) {
		*family = AF_INET6;
		return 0;
	}
	return -1;
}

/* The text of an address of a request, in buf of len bytes. buf, or NULL if
 * it does not fit. */
static inline const char *
map_ntop(int family, const struct in6_addr * a, char * buf, size_t len)
{
	if(family == AF_INET)
		return inet_ntop(AF_INET, a->s6_addr + 12, buf, len);
	return inet_ntop(AF_INET6, a, buf, len);
}

/* The filter of a remote host given as text: NULL, empty and "*" are any
 * host. 0, or -1 if host is no address. */
static inline int
map_filter_set(struct map_filter * f, const char * host, unsigned short rport)
{
	int family;
	memset(f, 0, sizeof(*f));
	f->rport = rport;
	if(host == NULL || host[0] == '\0' || strcmp(host, "*") == 0)
		return 0;
	if(map_pton(host, &family, &f->raddr) < 0)
		return -1;
	f->prefix = 128;
	return 0;
}

/* The text of the remote host of the first filter of r, in buf, or NULL
 * for any host: what the firewall functions take. */
static inline const char *
map_rhost(const struct lease_entry * r, char * buf, size_t len)
{
	const struct map_filter * f = r->nfilters > 0 ? &r->filters[0] : NULL;
	if(f == NULL || f->prefix == 0)
		return NULL;
	return map_ntop(IN6_IS_ADDR_V4MAPPED(&f->raddr) ? AF_INET : AF_INET6,
	                &f->raddr, buf, len);
}

/* TEMPORARY: only until the backends find their rules by key and hold no
 * description. Remove it then.
 *
 * The description of the firewall rule and of the lease file line of r,
 * from its kind: buf of len bytes holds it, or the label is returned as it
 * is. lease_entry_from_desc() reads it back. */
static inline const char *
map_rule_desc(const struct lease_entry * r, char * buf, size_t len)
{
	uint32_t w[MAP_NONCE_LEN / 4];

	switch(r->kind) {
	case MAP_KIND_PCP:
		/* each word of the nonce in host order, as PCP prints it */
		memcpy(w, r->nonce, sizeof(w));
		snprintf(buf, len, "PCP MAP %08x%08x%08x", w[0], w[1], w[2]);
		return buf;
	case MAP_KIND_NATPMP:
		snprintf(buf, len, "NAT-PMP %hu %s", r->eport, proto_itoa(r->proto));
		return buf;
	default:
		/* UPnP: the description of the client. WANIPv6FirewallControl
		 * gives none */
		if(r->family == AF_INET6)
			return "IGD2 pinhole";
		return r->label != NULL ? r->label : "";
	}
}

/* TEMPORARY, as map_rule_desc(): the description of the firewall rule of
 * r, "PCP PEER <nonce>", in buf of len bytes. */
static inline const char *
outgoing_rule_desc(const struct outgoing_entry * r, char * buf, size_t len)
{
	uint32_t w[MAP_NONCE_LEN / 4];

	/* each word of the nonce in host order, as PCP prints it */
	memcpy(w, r->nonce, sizeof(w));
	snprintf(buf, len, "PCP PEER %08x%08x%08x", w[0], w[1], w[2]);
	return buf;
}

/* For the lease file reloads only. Set the kind, nonce and label of r from
 * a description map_rule_desc() wrote, as a lease file keeps it. family, proto and eport must be set.
 * A description of no other kind is that of a UPnP client. */
static inline void
lease_entry_from_desc(struct lease_entry * r, const char * desc)
{
	static const char pcp[] = "PCP MAP ";
	const size_t n = sizeof(pcp) - 1;
	uint32_t w[MAP_NONCE_LEN / 4];
	char word[9], natpmp[32];
	int i;

	r->label = NULL;
	memset(r->nonce, 0, sizeof(r->nonce));
	if(strncmp(desc, pcp, n) == 0 && strlen(desc) == n + 24 &&
	   strspn(desc + n, "0123456789abcdefABCDEF") == 24) {
		word[8] = '\0';
		for(i = 0; i < MAP_NONCE_LEN / 4; i++) {
			memcpy(word, desc + n + 8 * i, 8);
			w[i] = (uint32_t)strtoul(word, NULL, 16);
		}
		memcpy(r->nonce, w, sizeof(w));
		r->kind = MAP_KIND_PCP;
		return;
	}
	r->kind = MAP_KIND_NATPMP;
	if(r->family == AF_INET &&
	   strcmp(desc, map_rule_desc(r, natpmp, sizeof(natpmp))) == 0)
		return;
	r->kind = MAP_KIND_UPNP;
	if(r->family == AF_INET)
		r->label = desc;
}

#endif
