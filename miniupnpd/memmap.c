/* MiniUPnP project
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

/* The lease table and the outgoing table, written as the firewall changes.
 * See memmap.h. */
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

#include "memmap.h"

/* 1 if the rules of e have no translation: an IPv6 map of the endpoint,
 * with a filter per rule */
static int
no_translation(const struct lease_entry * e)
{
	return e->family == AF_INET6 && e->eport == e->iport &&
	       memcmp(&e->eaddr, &e->iaddr, sizeof(e->iaddr)) == 0;
}

/* Only UPnP names its filters by a uid: PCP finds its own by its key and
 * remote. */
static void
uids_of_upnp_only(struct lease_entry * e)
{
	int i;
	if(e->kind == MAP_KIND_UPNP)
		return;
	for(i = 0; i < e->nfilters; i++)
		e->filters[i].uid = 0;
}

/* The remote of the one rule of a map with no filter: any host, any port. */
static const struct map_filter any_remote;

/* The filters of e go to map, the row of its endpoint: a filter of the same
 * remote takes the uid of e's, another one is added. A map with no filter
 * has one rule, of any remote: next to the filters of the other, that rule
 * becomes a filter of its own. map takes the expiry of e, which its filters
 * share. e is freed. */
static void
put_filters(struct lease_entry * map, struct lease_entry * e)
{
	int i;
	struct map_filter * f;
	const struct map_filter * filters = e->nfilters > 0 ? e->filters : &any_remote;
	const int nfilters = e->nfilters > 0 ? e->nfilters : 1;

	if(map->nfilters == 0 && e->nfilters > 0)
		lease_filter_add(map, &any_remote);
	for(i = 0; map->nfilters > 0 && i < nfilters; i++) {
		const struct map_filter * n = &filters[i];
		f = lease_filter_find(map, &n->raddr, n->prefix, n->rport);
		if(f == NULL)
			lease_filter_add(map, n);
		else if(n->uid != 0 && f->uid != n->uid)
			lease_filter_set_uid(f, n->uid);
	}
	lease_table_set_expiry(map, e->timestamp);
	lease_table_free(e);
}

/* e goes in the table in the place of old, the row of its rule, or as a new
 * row if there is none */
static void
put_row(struct lease_entry * e, struct lease_entry * old)
{
	struct lease_entry * stale;

	/* The firewall gave e its external port: another row of that port
	 * lost its rule without the table hearing of it (a flush, a failed
	 * read before a delete). It goes, so the external key stays unique. */
	if(!no_translation(e)) {
		stale = lease_table_find_mapping(e->proto, e->family, &e->eaddr, e->eport);
		if(stale != NULL && stale != old)
			lease_table_remove(stale);
	}
	if(old == NULL)
		lease_table_link(e);
	else if(no_translation(e))
		put_filters(old, e);
	else
		lease_table_link_in_place(e, old);
}

void
memmap_add(struct lease_entry * e)
{
	if(!e->row)
		return;
	uids_of_upnp_only(e);
	/* A new rule of a mapping has no row; one there is was left by a
	 * rule the firewall lost, and the new rule takes its place. A new rule
	 * without translation is a filter of the map of its endpoint. */
	put_row(e, lease_table_find_entry(e->proto, e->family, &e->iaddr,
	                                  e->iport, e->eport));
}

void
memmap_update(struct lease_entry * e, unsigned short iport_old)
{
	if(!e->row)
		return;
	uids_of_upnp_only(e);
	/* the row of the rule as it was: UPnP may have changed its internal
	 * port. A rule the table did not know becomes a row. */
	put_row(e, lease_table_find_entry(e->proto, e->family, &e->iaddr, iport_old,
	                                  no_translation(e) ? iport_old : e->eport));
}

void
memmap_renew(const struct lease_entry * r)
{
	struct lease_entry * e = lease_table_find_entry(r->proto, r->family, &r->iaddr,
	                                                r->iport, r->eport);
	if(e != NULL)
		lease_table_set_expiry(e, r->timestamp);
}

void
memmap_delete(int proto, int family, const struct in6_addr * iaddr,
              unsigned short iport, unsigned short eport)
{
	struct lease_entry * e = lease_table_find_entry(proto, family, iaddr, iport, eport);
	if(e != NULL)
		lease_table_remove(e);
}

void
memmap_delete_filter(const struct lease_entry * r)
{
	/* a rule of no filter is the rule of any remote */
	const struct map_filter * k = r->nfilters > 0 ? &r->filters[0] : &any_remote;
	struct map_filter * f = NULL;
	struct lease_entry * e;

	if(k->uid != 0)
		f = lease_table_find_uid(k->uid);
	if(f == NULL) {
		e = lease_table_find_entry(r->proto, r->family, &r->iaddr, r->iport, r->iport);
		if(e == NULL)
			return;
		/* a map with no filter: its one rule is of any remote */
		if(e->nfilters == 0) {
			if(k->prefix == 0 && k->rport == 0)
				lease_table_remove(e);
			return;
		}
		f = lease_filter_find(e, &k->raddr, k->prefix, k->rport);
		if(f == NULL)
			return;
	}
	e = f->map;
	if(e->nfilters <= 1)
		lease_table_remove(e);
	else
		lease_filter_drop(e, f);
}

void
memmap_pinhole_expired(int proto, const struct in6_addr * iaddr, unsigned short iport,
                       const struct in6_addr * raddr, unsigned short rport,
                       unsigned short uid)
{
	struct lease_entry r;
	struct map_filter f;

	lease_entry_init(&r, 0, NULL);
	r.family = AF_INET6;
	r.proto = proto;
	r.iaddr = r.eaddr = *iaddr;
	r.iport = r.eport = iport;
	memset(&f, 0, sizeof(f));
	f.raddr = *raddr;
	f.prefix = IN6_IS_ADDR_UNSPECIFIED(raddr) ? 0 : 128;
	f.rport = rport;
	f.uid = uid;
	r.filters = &f;
	r.nfilters = 1;
	memmap_delete_filter(&r);
}

void
memmap_link_outgoing(struct outgoing_entry * b)
{
	if(!b->row)
		return;
	outgoing_table_link(b);
}

void
memmap_drop_outgoing(const struct outgoing_entry * key,
                     const struct in6_addr * raddr, unsigned short rport)
{
	struct outgoing_entry * b;
	struct outgoing_peer * p;

	b = outgoing_table_find(key);
	if(b == NULL)
		return;
	p = outgoing_table_find_peer(b, raddr, rport);
	if(p != NULL)
		outgoing_table_remove_peer(b, p);
}

void
memmap_outgoing_expired(unsigned int now)
{
	outgoing_table_expire(now);
}

struct lease_entry *
memmap_find_map(int proto, int family, const struct in6_addr * eaddr,
                unsigned short eport)
{
	struct lease_entry * e = lease_table_find_mapping(proto, family, eaddr, eport);
	if(e == NULL && !IN6_IS_ADDR_UNSPECIFIED(eaddr))
		e = lease_table_find_mapping(proto, family, &in6addr_any, eport);
	return e;
}

struct lease_entry *
memmap_eport_used_by_other(int family, const struct in6_addr * eaddr,
                           unsigned short eport, const struct in6_addr * iaddr)
{
	struct lease_entry * e = lease_table_port_used_by_other(family, eaddr, eport, iaddr);
	if(e == NULL && !IN6_IS_ADDR_UNSPECIFIED(eaddr))
		e = lease_table_port_used_by_other(family, &in6addr_any, eport, iaddr);
	return e;
}

struct lease_entry *
memmap_next_client_map(const struct lease_entry * prev, int proto, int family,
                       const struct in6_addr * iaddr, unsigned short iport)
{
	struct lease_entry * e;

	if(iport != 0)
		return lease_table_next_internal(prev, proto, family, iaddr, iport);
	for(e = lease_table_next_port(prev); e != NULL; e = lease_table_next_port(e))
		if(e->proto == proto && e->family == family &&
		   memcmp(&e->iaddr, iaddr, sizeof(*iaddr)) == 0)
			return e;
	return NULL;
}

struct outgoing_entry *
memmap_find_peer(int proto, int family, const struct in6_addr * iaddr,
                 unsigned short iport, const struct in6_addr * raddr,
                 unsigned short rport)
{
	struct outgoing_entry * b;

	for(b = outgoing_table_next(NULL); b != NULL; b = outgoing_table_next(b))
		if(b->proto == proto && b->family == family && b->iport == iport &&
		   memcmp(&b->iaddr, iaddr, sizeof(*iaddr)) == 0 &&
		   (raddr == NULL || outgoing_table_find_peer(b, raddr, rport) != NULL))
			return b;
	return NULL;
}

static struct outgoing_entry *
peer_port_used_by_other(int family, const struct in6_addr * eaddr,
                        unsigned short eport, const struct in6_addr * iaddr)
{
	struct outgoing_entry * b;

	for(b = outgoing_table_next(NULL); b != NULL; b = outgoing_table_next(b))
		if(b->family == family && b->eport == eport &&
		   memcmp(&b->eaddr, eaddr, sizeof(*eaddr)) == 0 &&
		   memcmp(&b->iaddr, iaddr, sizeof(*iaddr)) != 0)
			return b;
	return NULL;
}

struct outgoing_entry *
memmap_peer_port_used_by_other(int family, const struct in6_addr * eaddr,
                               unsigned short eport, const struct in6_addr * iaddr)
{
	struct outgoing_entry * b = peer_port_used_by_other(family, eaddr, eport, iaddr);
	if(b == NULL && !IN6_IS_ADDR_UNSPECIFIED(eaddr))
		b = peer_port_used_by_other(family, &in6addr_any, eport, iaddr);
	return b;
}

/* the rows of each kind, and those past their expiry */
struct map_stats {
	unsigned int now;
	unsigned int kind[MAP_KIND_UPNP + 1];
	unsigned int ipv4, ipv6;
	unsigned int expired;
};

static void
count_row(struct lease_entry * e, void * arg)
{
	struct map_stats * s = arg;

	if(e->kind <= MAP_KIND_UPNP)
		s->kind[e->kind]++;
	if(e->family == AF_INET)
		s->ipv4++;
	else
		s->ipv6++;
	if(e->timestamp != 0 && e->timestamp <= s->now)
		s->expired++;
}

int
memmap_stats(const char * path, unsigned int now, unsigned int next_expiry)
{
	char tmp[PATH_MAX];
	struct map_stats s;
	const struct outgoing_entry * b;
	unsigned int out4 = 0, out6 = 0;
	FILE * f;
	int r;

	if(snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp))
		return -1;
	f = fopen(tmp, "w");
	if(f == NULL) {
		syslog(LOG_WARNING, "memmap: cannot write %s: %m", tmp);
		return -1;
	}
	memset(&s, 0, sizeof(s));
	s.now = now;
	lease_table_foreach(count_row, &s);
	for(b = outgoing_table_next(NULL); b != NULL; b = outgoing_table_next(b)) {
		if(b->family == AF_INET)
			out4++;
		else
			out6++;
	}
	fprintf(f, "map %u\nmap_pcp %u\nmap_natpmp %u\nmap_upnp %u\n"
	        "map_ipv4 %u\nmap_ipv6 %u\nmap_expired %u\nmap_filters %u\n"
	        "outgoing_bindings %u\noutgoing_bindings_ipv4 %u\n"
	        "outgoing_bindings_ipv6 %u\noutgoing %u\n",
	        lease_table_count(), s.kind[MAP_KIND_PCP], s.kind[MAP_KIND_NATPMP],
	        s.kind[MAP_KIND_UPNP], s.ipv4, s.ipv6, s.expired,
	        lease_table_filter_count(), outgoing_table_count(), out4, out6,
	        outgoing_table_peer_count());
	if(next_expiry != 0)
		fprintf(f, "next_expiry %ld\n", (long)next_expiry - (long)now);
	r = ferror(f) ? -1 : 0;
	if(fclose(f) != 0)
		r = -1;
	if(r == 0 && rename(tmp, path) < 0)
		r = -1;
	if(r < 0) {
		syslog(LOG_WARNING, "memmap: cannot write %s", path);
		unlink(tmp);
	}
	return r;
}

int
memmap_dump(const char * path)
{
	FILE * f;
	int r;

	f = fopen(path, "w");
	if(f == NULL) {
		syslog(LOG_WARNING, "memmap: cannot write %s: %m", path);
		return -1;
	}
	lease_table_dump(f);
	outgoing_table_dump(f);
	r = ferror(f) ? -1 : 0;
	if(fclose(f) != 0)
		r = -1;
	if(r < 0)
		syslog(LOG_WARNING, "memmap: cannot write %s", path);
	return r;
}
