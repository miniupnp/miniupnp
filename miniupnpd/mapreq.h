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
 * firewall rule is no part of it. */
#ifndef MAPREQ_H_INCLUDED
#define MAPREQ_H_INCLUDED

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
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

/* One remote a mapping lets in. A mapping with no filter lets any remote
 * in. */
struct map_filter {
	struct in6_addr raddr;	/* IPv4 as ::ffff:a.b.c.d */
	unsigned char prefix;	/* the prefix length of raddr, on 128 bits
				 * also for IPv4. 0 : any host */
	unsigned short rport;	/* 0 : any port */
	unsigned short uid;	/* the UniqueID of a UPnP IPv6 rule, 0 : none.
				 * Set by upnp_add_inboundpinhole() */
};

struct lease_entry {
	unsigned char kind;	/* enum map_kind */
	unsigned char nonce[MAP_NONCE_LEN];	/* PCP, else zero */
	unsigned char flags;	/* MAP_* bits */
	int family;		/* of the internal side: AF_INET, AF_INET6 */
	int proto;		/* IPPROTO_TCP, IPPROTO_UDP, IPPROTO_UDPLITE */
	struct in6_addr iaddr;
	unsigned short iport;
	/* The external side. IPv4: the WAN address, :: for that of
	 * ext_if_name. IPv6 with no translation: iaddr and iport. eport is the
	 * port asked for, 0 : any, and the port used once it is mapped. */
	struct in6_addr eaddr;
	unsigned short eport;
	struct map_filter * filters;	/* the caller's array. IPv4: NULL : any
					 * remote. IPv6: always one filter, which
					 * carries the uid; prefix 0 : any remote */
	int nfilters;
	const char * label;	/* the text of the client: the UPnP description,
				 * the PCP DESCRIPTION option. NULL : none.
				 * The rule gets map_rule_desc() */
	unsigned int timestamp;	/* the expiry on the clock of upnp_time(),
				 * 0 : none */
};

/* An empty request of a protocol. nonce NULL : zero. */
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
