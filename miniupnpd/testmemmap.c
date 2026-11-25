/* unit test of memmap.c */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include "memmap.h"

static struct in6_addr
addr(const char * s)
{
	struct in6_addr a;
	assert(inet_pton(AF_INET6, s, &a) == 1);
	return a;
}

/* a staged IPv4 row of iaddr:iport on eport, as a protocol fills it */
static struct lease_entry *
row4(int kind, unsigned short eport, const char * iaddr, unsigned short iport)
{
	struct lease_entry * e = lease_table_new(0);
	assert(e != NULL);
	lease_entry_set_kind(e, kind, NULL);
	e->family = AF_INET;
	e->proto = IPPROTO_TCP;
	e->iaddr = addr(iaddr);
	e->iport = iport;
	e->eport = eport;
	return e;
}

/* a staged IPv6 row of iaddr:iport with one filter raddr, uid */
static struct lease_entry *
row6(const char * iaddr, unsigned short iport, const char * raddr,
     unsigned short uid, unsigned int timestamp)
{
	struct lease_entry * e = lease_table_new(1);
	assert(e != NULL);
	lease_entry_set_kind(e, MAP_KIND_UPNP, NULL);
	e->family = AF_INET6;
	e->proto = IPPROTO_UDP;
	e->iaddr = e->eaddr = addr(iaddr);
	e->iport = e->eport = iport;
	e->filters[0].raddr = addr(raddr);
	e->filters[0].prefix = 128;
	e->filters[0].uid = uid;
	e->timestamp = timestamp;
	return e;
}

/* IPv4: a row per mapping, found by its key and external port */
static void
test_ipv4(void)
{
	static const char label[] = "game";
	struct in6_addr h10 = addr("::ffff:192.0.2.10"), h11 = addr("::ffff:192.0.2.11");
	struct in6_addr any4 = addr("::ffff:0.0.0.0"), wan = addr("::ffff:198.51.100.1");
	struct lease_entry * e, * r, * a, * b, req;
	unsigned long long id;

	lease_table_clear();
	e = row4(MAP_KIND_PCP, 5000, "::ffff:192.0.2.10", 80);
	e->eaddr = addr("::ffff:198.51.100.1");	/* the address PCP asked for */
	memmap_add(e);
	assert(lease_table_find_entry(IPPROTO_TCP, AF_INET, &h10, 80, 5000) == e);
	/* the row keeps the external address it was given: there can be
	 * several WAN addresses */
	assert(lease_table_find_mapping(IPPROTO_TCP, AF_INET, &wan, 5000) == e);
	assert(lease_table_find_mapping(IPPROTO_TCP, AF_INET, &any4, 5000) == NULL);
	/* an update which changes the internal port: the row of the rule as
	 * it was takes the new values in place, with a copy of the label */
	r = row4(MAP_KIND_UPNP, 5000, "::ffff:192.0.2.10", 81);
	r->label = label;
	id = e->id;
	memmap_update(r, 80);	/* e is freed */
	assert(lease_table_count() == 1);
	assert(lease_table_find_entry(IPPROTO_TCP, AF_INET, &h10, 80, 5000) == NULL);
	assert(lease_table_find_entry(IPPROTO_TCP, AF_INET, &h10, 81, 5000) == r);
	assert(r->label != label && strcmp(r->label, "game") == 0 && r->id == id);
	/* one internal endpoint on two external ports: two rows, and the
	 * delete of one leaves the other */
	a = row4(MAP_KIND_UPNP, 8080, "::ffff:192.0.2.11", 80);
	b = row4(MAP_KIND_UPNP, 8081, "::ffff:192.0.2.11", 80);
	memmap_add(a);
	memmap_add(b);
	assert(lease_table_count() == 3);
	memmap_delete(IPPROTO_TCP, AF_INET, &h11, 80, 8081);
	assert(lease_table_find_entry(IPPROTO_TCP, AF_INET, &h11, 80, 8080) == a);
	assert(lease_table_find_entry(IPPROTO_TCP, AF_INET, &h11, 80, 8081) == NULL);
	/* a renewal of the rule of a key and eport */
	lease_entry_init(&req, MAP_KIND_UPNP, NULL);
	req.family = AF_INET;
	req.proto = IPPROTO_TCP;
	req.iaddr = h11;
	req.iport = 80;
	req.eport = 8080;
	req.timestamp = 777;
	memmap_renew(&req);
	assert(a->timestamp == 777);
	/* a request on the stack is not recorded */
	req.eport = 6000;
	memmap_add(&req);
	assert(lease_table_count() == 2);
	/* the deletes */
	memmap_delete(IPPROTO_UDP, AF_INET, &h10, 81, 5000);	/* other proto: nothing */
	assert(lease_table_count() == 2);
	memmap_delete(IPPROTO_TCP, AF_INET, &h10, 81, 5000);
	memmap_delete(IPPROTO_TCP, AF_INET, &h11, 80, 8080);
	assert(lease_table_count() == 0);
	lease_table_clear();
}

/* IPv6 NAT66: a mapping is a row, as in IPv4 */
static void
test_nat66(void)
{
	struct in6_addr i = addr("2001:db8::10");
	struct lease_entry * a, * b;

	lease_table_clear();
	a = row6("2001:db8::10", 4000, "::", 0, 100);
	a->kind = MAP_KIND_PCP;
	a->eaddr = addr("2001:db8:ffff::1");
	a->eport = 5000;
	a->nfilters = 0;
	b = row6("2001:db8::10", 4000, "::", 0, 100);
	b->kind = MAP_KIND_PCP;
	b->eaddr = addr("2001:db8:ffff::1");
	b->eport = 5001;
	b->nfilters = 0;
	memmap_add(a);
	memmap_add(b);
	assert(lease_table_count() == 2);
	memmap_delete(IPPROTO_UDP, AF_INET6, &i, 4000, 5000);
	assert(lease_table_count() == 1 &&
	       lease_table_find_entry(IPPROTO_UDP, AF_INET6, &i, 4000, 5001) == b);
	lease_table_clear();
}

/* IPv6 without translation: the rules of one internal endpoint are the
 * filters of one map, found by their remote; only UPnP keeps a uid */
static void
test_ipv6(void)
{
	struct lease_entry * m, * p, req;
	struct map_filter * f, rf;
	struct in6_addr i = addr("2001:db8::10"), r1 = addr("2001:db8:1::1");

	lease_table_clear();
	m = row6("2001:db8::10", 4000, "2001:db8:1::1", 5, 100);
	memmap_add(m);
	assert(lease_table_count() == 1 && lease_table_find_uid(5)->map == m);
	/* another remote of the same endpoint: a filter of the same map */
	memmap_add(row6("2001:db8::10", 4000, "2001:db8:1::2", 6, 200));
	assert(lease_table_count() == 1 && m->nfilters == 2);
	assert(lease_table_find_uid(6)->map == m && m->timestamp == 200);
	/* the update of the pinhole of a remote: its filter takes the uid */
	memmap_update(row6("2001:db8::10", 4000, "2001:db8:1::1", 7, 300), 4000);
	assert(m->nfilters == 2 && lease_table_find_uid(5) == NULL && m->timestamp == 300);
	f = lease_table_find_uid(7);
	assert(f != NULL && memcmp(&f->raddr, &r1, sizeof(r1)) == 0);
	/* a renewal by the key: the map takes the expiry */
	lease_entry_init(&req, MAP_KIND_UPNP, NULL);
	req.family = AF_INET6;
	req.proto = IPPROTO_UDP;
	req.iaddr = req.eaddr = i;
	req.iport = req.eport = 4000;
	req.timestamp = 400;
	memmap_renew(&req);
	assert(m->timestamp == 400);
	/* the delete of a UPnP pinhole by its uid */
	memset(&rf, 0, sizeof(rf));
	rf.uid = 7;
	req.filters = &rf;
	req.nfilters = 1;
	memmap_delete_filter(&req);
	assert(lease_table_count() == 1 && m->nfilters == 1);
	/* PCP: no uid in the table; the delete by its remote, the map with its
	 * last filter */
	p = row6("2001:db8::20", 4100, "::", 9, 500);
	p->kind = MAP_KIND_PCP;
	p->filters[0].prefix = 0;	/* any remote */
	memmap_add(p);
	assert(lease_table_count() == 2 && p->filters[0].uid == 0 && lease_table_find_uid(9) == NULL);
	req.iaddr = req.eaddr = addr("2001:db8::20");
	req.iport = req.eport = 4100;
	memset(&rf, 0, sizeof(rf));
	memmap_delete_filter(&req);
	assert(lease_table_count() == 1);
	/* the last UPnP filter: the map goes */
	req.iaddr = req.eaddr = i;
	req.iport = req.eport = 4000;
	rf.uid = 6;
	memmap_delete_filter(&req);
	assert(lease_table_count() == 0);
	lease_table_clear();
}

/* the pinholes the backend expires: by the uid for UPnP, by the key and
 * remote for PCP, which has no uid in the table */
static void
test_expired(void)
{
	struct in6_addr i = addr("2001:db8::10"), j = addr("2001:db8::20");
	struct in6_addr r1 = addr("2001:db8:1::1"), any = addr("::");
	struct lease_entry * m, * p;

	lease_table_clear();
	m = row6("2001:db8::10", 4000, "2001:db8:1::1", 5, 100);
	memmap_add(m);
	memmap_add(row6("2001:db8::10", 4000, "2001:db8:1::2", 6, 100));
	p = row6("2001:db8::20", 4100, "::", 9, 100);
	p->kind = MAP_KIND_PCP;
	p->filters[0].prefix = 0;
	memmap_add(p);
	assert(lease_table_count() == 2 && m->nfilters == 2);
	memmap_pinhole_expired(IPPROTO_UDP, &i, 4000, &r1, 0, 5);
	assert(lease_table_count() == 2 && m->nfilters == 1 && lease_table_find_uid(5) == NULL);
	/* PCP: the backend's uid is not in the table, the remote finds it */
	memmap_pinhole_expired(IPPROTO_UDP, &j, 4100, &any, 0, 9);
	assert(lease_table_count() == 1);
	memmap_pinhole_expired(IPPROTO_UDP, &j, 4100, &any, 0, 9);	/* gone: nothing */
	assert(lease_table_count() == 1);
	lease_table_clear();
}

/* a staged PCP IPv6 map of iaddr:iport without FILTER: no filter, its one
 * rule lets any remote in */
static struct lease_entry *
map6_any(const char * iaddr, unsigned short iport, unsigned int timestamp)
{
	struct lease_entry * e = lease_table_new(0);
	assert(e != NULL);
	lease_entry_set_kind(e, MAP_KIND_PCP, NULL);
	e->family = AF_INET6;
	e->proto = IPPROTO_UDP;
	e->iaddr = e->eaddr = addr(iaddr);
	e->iport = e->eport = iport;
	e->timestamp = timestamp;
	return e;
}

/* An IPv6 map with no filter: one row of no filter, renewed by its key,
 * deleted by a request of no filter or of any remote, and expired by the
 * backend's any remote. */
static void
test_ipv6_no_filter(void)
{
	struct in6_addr i = addr("2001:db8::30"), any = addr("::");
	struct lease_entry * p, req;
	struct map_filter rf;

	lease_table_clear();
	p = map6_any("2001:db8::30", 4200, 100);
	memmap_add(p);
	assert(lease_table_count() == 1 && p->nfilters == 0 && lease_table_filter_count() == 0);
	/* the renewal through the add path: still no filter */
	memmap_update(map6_any("2001:db8::30", 4200, 200), 4200);	/* p takes it */
	assert(lease_table_count() == 1 && p->nfilters == 0 && p->timestamp == 200);
	/* a renewal by the key */
	lease_entry_init(&req, MAP_KIND_PCP, NULL);
	req.family = AF_INET6;
	req.proto = IPPROTO_UDP;
	req.iaddr = req.eaddr = i;
	req.iport = req.eport = 4200;
	req.timestamp = 300;
	memmap_renew(&req);
	assert(p->timestamp == 300);
	/* a remote is no rule of it: nothing */
	map_filter_set(&rf, "2001:db8:1::1", 0);
	req.filters = &rf;
	req.nfilters = 1;
	memmap_delete_filter(&req);
	assert(lease_table_count() == 1);
	/* the delete of PCP: a request of no filter */
	req.filters = NULL;
	req.nfilters = 0;
	memmap_delete_filter(&req);
	assert(lease_table_count() == 0);
	/* the delete of UPnP DeletePinhole: any remote, a uid the table does
	 * not know */
	memmap_add(map6_any("2001:db8::30", 4200, 100));
	map_filter_set(&rf, NULL, 0);
	rf.uid = 9;
	req.filters = &rf;
	req.nfilters = 1;
	memmap_delete_filter(&req);
	assert(lease_table_count() == 0);
	/* the expiry by the backend */
	memmap_add(map6_any("2001:db8::30", 4200, 100));
	memmap_pinhole_expired(IPPROTO_UDP, &i, 4200, &any, 0, 9);
	assert(lease_table_count() == 0);
	lease_table_clear();
}

/* A UPnP pinhole on the endpoint of a map with no filter, and the other way
 * round: the rule of any remote becomes a filter of its own, so the map
 * still lets any remote in. */
static void
test_ipv6_no_filter_and_pinhole(void)
{
	struct in6_addr r1 = addr("2001:db8:1::1"), any = addr("::");
	struct lease_entry * p, * m, req;

	lease_table_clear();
	p = map6_any("2001:db8::10", 4000, 100);
	memmap_add(p);
	memmap_add(row6("2001:db8::10", 4000, "2001:db8:1::1", 5, 200));
	assert(lease_table_count() == 1 && p->nfilters == 2);
	assert(lease_filter_find(p, &any, 0, 0) != NULL && lease_filter_find(p, &any, 0, 0)->uid == 0);
	assert(lease_filter_find(p, &r1, 128, 0) == lease_table_find_uid(5));
	/* the delete of the PCP rule leaves the pinhole */
	lease_entry_init(&req, MAP_KIND_PCP, NULL);
	req.family = AF_INET6;
	req.proto = IPPROTO_UDP;
	req.iaddr = req.eaddr = addr("2001:db8::10");
	req.iport = req.eport = 4000;
	memmap_delete_filter(&req);
	assert(lease_table_count() == 1 && p->nfilters == 1 && lease_table_find_uid(5)->map == p);
	lease_table_clear();

	m = row6("2001:db8::10", 4000, "2001:db8:1::1", 5, 100);
	memmap_add(m);
	memmap_add(map6_any("2001:db8::10", 4000, 200));
	assert(lease_table_count() == 1 && m->nfilters == 2 && m->timestamp == 200);
	assert(lease_filter_find(m, &any, 0, 0) != NULL);
	/* again: the same rule, no new filter */
	memmap_update(map6_any("2001:db8::10", 4000, 300), 4000);
	assert(lease_table_count() == 1 && m->nfilters == 2 && m->timestamp == 300);
	memmap_delete_filter(&req);
	assert(lease_table_count() == 1 && m->nfilters == 1 && lease_table_find_uid(5) == &m->filters[0]);
	lease_table_clear();
}

/* A new rule on an external port whose row lost its rule without the table
 * hearing of it (a flush): the stale row goes, the external key stays
 * unique. Another WAN address is another key. */
static void
test_stale(void)
{
	struct in6_addr h10 = addr("::ffff:192.0.2.10"), h11 = addr("::ffff:192.0.2.11");
	struct in6_addr wan = addr("::ffff:198.51.100.1");
	struct lease_entry * a, * b, * c;

	lease_table_clear();
	a = row4(MAP_KIND_UPNP, 5000, "::ffff:192.0.2.10", 80);
	a->eaddr = wan;
	memmap_add(a);
	c = row4(MAP_KIND_UPNP, 5000, "::ffff:192.0.2.11", 81);
	c->eaddr = addr("::ffff:198.51.100.2");
	memmap_add(c);
	assert(lease_table_count() == 2);
	b = row4(MAP_KIND_PCP, 5000, "::ffff:192.0.2.11", 82);
	b->eaddr = wan;
	memmap_add(b);	/* a is freed */
	assert(lease_table_count() == 2);
	assert(lease_table_find_entry(IPPROTO_TCP, AF_INET, &h10, 80, 5000) == NULL);
	assert(lease_table_find_mapping(IPPROTO_TCP, AF_INET, &wan, 5000) == b);
	assert(lease_table_find_entry(IPPROTO_TCP, AF_INET, &h11, 81, 5000) == c);
	lease_table_clear();
}

/* PEER: bindings on the any address, peers removed one by one */
static void
test_outgoing(void)
{
	struct outgoing_entry * b, key;
	struct in6_addr p1 = addr("::ffff:203.0.113.1"), p2 = addr("::ffff:203.0.113.2");
	int i;

	outgoing_table_clear();
	for(i = 0; i < 2; i++) {
		b = outgoing_table_new(1);
		assert(b != NULL);
		b->family = AF_INET;
		b->proto = IPPROTO_UDP;
		b->iaddr = addr("::ffff:192.0.2.10");
		b->iport = 5000;
		b->eaddr = addr("::ffff:0.0.0.0");
		b->eport = 6000;
		b->peers[0].raddr = i ? p2 : p1;
		b->peers[0].rport = 80;
		memmap_link_outgoing(b);
	}
	assert(outgoing_table_count() == 1 && outgoing_table_peer_count() == 2);
	memset(&key, 0, sizeof(key));
	key.family = AF_INET;
	key.proto = IPPROTO_UDP;
	key.iaddr = addr("::ffff:192.0.2.10");
	key.iport = 5000;
	key.eaddr = addr("::ffff:0.0.0.0");
	key.eport = 6000;
	memmap_drop_outgoing(&key, &p1, 80);
	assert(outgoing_table_count() == 1 && outgoing_table_peer_count() == 1);
	memmap_drop_outgoing(&key, &p1, 80);	/* gone already: nothing */
	memmap_drop_outgoing(&key, &p2, 80);
	assert(outgoing_table_count() == 0);
	outgoing_table_clear();
}

/* the dump: both tables in one file */
static void
test_dump(void)
{
	char path[] = "/tmp/testmemmap.XXXXXX";
	char line[256];
	FILE * f;
	int fd, lease = 0, outgoing = 0;

	lease_table_clear();
	outgoing_table_clear();
	memmap_add(row4(MAP_KIND_NATPMP, 5000, "::ffff:192.0.2.10", 80));
	fd = mkstemp(path);
	assert(fd >= 0);
	close(fd);
	assert(memmap_dump(path) == 0);
	f = fopen(path, "r");
	assert(f != NULL);
	while(fgets(line, sizeof(line), f) != NULL) {
		if(strncmp(line, "# lease table: 1 rows", 21) == 0)
			lease++;
		if(strncmp(line, "# outgoing table: 0 bindings", 28) == 0)
			outgoing++;
	}
	fclose(f);
	unlink(path);
	assert(lease == 1 && outgoing == 1);
	assert(memmap_dump("/nonexistent/dir/dump") == -1);
	lease_table_clear();
}

int
main(void)
{
	test_ipv4();
	test_nat66();
	test_ipv6();
	test_expired();
	test_ipv6_no_filter();
	test_ipv6_no_filter_and_pinhole();
	test_stale();
	test_outgoing();
	test_dump();
	printf("testmemmap: OK\n");
	return 0;
}
