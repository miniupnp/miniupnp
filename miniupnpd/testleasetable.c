/* unit test of lease_table.c */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include "lease_table.h"

static struct in6_addr
addr(const char * s)
{
	struct in6_addr a;
	assert(inet_pton(AF_INET6, s, &a) == 1);
	return a;
}

/* An unlinked IPv4 row with nfilters empty filters, as a protocol fills it.
 * nonce: the last byte of the PCP nonce. */
static struct lease_entry *
newrow(int kind, int proto, unsigned short eport, const char * iaddr,
       unsigned short iport, unsigned char nonce, int nfilters)
{
	struct lease_entry * e = lease_table_new(nfilters);
	assert(e != NULL);
	e->kind = (unsigned char)kind;
	e->family = AF_INET;
	e->proto = proto;
	e->eport = eport;
	e->iport = iport;
	e->iaddr = addr(iaddr);
	e->nonce[11] = nonce;
	return e;
}

/* the same, linked */
static struct lease_entry *
add(int kind, int proto, unsigned short eport, const char * iaddr,
    unsigned short iport, unsigned char nonce)
{
	struct lease_entry * e = newrow(kind, proto, eport, iaddr, iport, nonce, 0);
	lease_table_link(e);
	return e;
}

/* A linked IPv6 map of iaddr:iport with one filter of uid uid, any remote. */
static struct lease_entry *
add6(int kind, const char * iaddr, unsigned short iport, unsigned short uid)
{
	struct lease_entry * e = lease_table_new(1);
	assert(e != NULL);
	e->kind = (unsigned char)kind;
	e->family = AF_INET6;
	e->proto = IPPROTO_UDP;
	e->iaddr = e->eaddr = addr(iaddr);
	e->iport = e->eport = iport;
	e->filters[0].uid = uid;
	lease_table_link(e);
	return e;
}

static void
counter(struct lease_entry * e, void * arg)
{
	(void)e;
	(*(unsigned int *)arg)++;
}

/* a new uid skips the uids filters hold */
static void
test_new_uid(void)
{
	unsigned short u1, u2;
	lease_table_clear();
	u1 = lease_table_new_uid();
	assert(u1 != 0);
	add6(MAP_KIND_UPNP, "2001:db8::1", 4000, (unsigned short)(u1 + 1));
	u2 = lease_table_new_uid();
	assert(u2 != 0 && u2 != u1 + 1);
	lease_table_clear();
}

/* with every uid in use there is none to give, and a freed one comes back */
static void
test_uids_full(void)
{
	struct lease_entry * x = NULL;
	struct map_filter * f;
	char a[INET6_ADDRSTRLEN];
	unsigned int i;
	lease_table_clear();
	for(i = 1; i <= 65534; i++) {
		snprintf(a, sizeof(a), "2001:db8::%x", i);
		x = add6(MAP_KIND_UPNP, a, 4000, (unsigned short)i);
	}
	/* each uid gives its filter, and the filter its map */
	for(i = 1; i <= 65534; i++) {
		f = lease_table_find_uid((unsigned short)i);
		assert(f != NULL && f->uid == i && f->map->filters == f);
	}
	assert(lease_table_new_uid() == 0);
	lease_table_remove(x);
	assert(lease_table_new_uid() == 65534);
	lease_table_clear();
	assert(lease_table_new_uid() != 0);
}

/* PCP IPv6 maps take no uid, so there can be more of them than uids */
static void
test_pcp_no_uid(void)
{
	unsigned short u;
	char a[INET6_ADDRSTRLEN];
	int i;
	lease_table_clear();
	for(i = 0; i < 70000; i++) {
		snprintf(a, sizeof(a), "2001:db8::%x:%x", i >> 16, i & 0xffff);
		add6(MAP_KIND_PCP, a, 4000, 0);
	}
	assert(lease_table_count() == 70000 && lease_table_filter_count() == 70000);
	u = lease_table_new_uid();
	assert(u != 0 && lease_table_find_uid(u) == NULL);
	lease_table_clear();
}

static void
test_ids(void)
{
	struct lease_entry * a, * b, * c;
	lease_table_clear();
	a = add(MAP_KIND_UPNP, 6, 5000, "::ffff:192.0.2.1", 80, 0);
	assert(a->id != 0);
	b = add(MAP_KIND_UPNP, 6, 5001, "::ffff:192.0.2.1", 80, 0);
	assert(b->id > a->id);
	/* a row in the place of another keeps its id */
	c = newrow(MAP_KIND_UPNP, 6, 5001, "::ffff:192.0.2.1", 81, 0, 0);
	lease_table_link_in_place(c, b);
	assert(c->id == a->id + 1);
	/* a loaded row keeps its id, and the next one goes on after it */
	b = newrow(MAP_KIND_UPNP, 6, 5002, "::ffff:192.0.2.1", 80, 0, 0);
	b->id = c->id + 1000;
	lease_table_link(b);
	assert(b->id == c->id + 1000);
	b = add(MAP_KIND_UPNP, 6, 5003, "::ffff:192.0.2.1", 80, 0);
	assert(b->id == c->id + 1001);
	/* the ids the files of the last run hold are not given again */
	lease_table_reserve_ids(b->id + 50);
	a = add(MAP_KIND_UPNP, 6, 5004, "::ffff:192.0.2.1", 80, 0);
	assert(a->id == b->id + 51);
	lease_table_reserve_ids(1);	/* never lowers it */
	a = add(MAP_KIND_UPNP, 6, 5005, "::ffff:192.0.2.1", 80, 0);
	assert(a->id == b->id + 52);
	lease_table_clear();
}

/* Each change of a linked row counts in the tables it is in. */
static void
test_changes(void)
{
	struct lease_entry * a;
	unsigned long m, flt;
	lease_table_clear();
	m = lease_table_changes(LEASE_T_MAPPINGS);
	flt = lease_table_changes(LEASE_T_FILTERS);
	a = newrow(MAP_KIND_UPNP, 6, 6000, "::ffff:192.0.2.1", 80, 0, 0);
	/* an unlinked row counts nothing */
	a->label = "x";	/* the caller's until the link */
	lease_table_set_expiry(a, 50);
	assert(lease_table_changes(LEASE_T_MAPPINGS) == m);
	lease_table_link(a);
	assert(lease_table_changes(LEASE_T_MAPPINGS) == m + 1);
	assert(lease_table_changes(LEASE_T_FILTERS) == flt);
	lease_table_set_expiry(a, 100);
	assert(a->timestamp == 100 && lease_table_changes(LEASE_T_MAPPINGS) == m + 2);
	assert(lease_table_set_label(a, "y") == 0);
	assert(lease_table_changes(LEASE_T_MAPPINGS) == m + 3);
	lease_table_remove(a);
	assert(lease_table_changes(LEASE_T_MAPPINGS) == m + 4);
	/* a row with a filter has a line in Filters too */
	a = newrow(MAP_KIND_UPNP, 6, 6000, "::ffff:192.0.2.1", 80, 0, 1);
	a->filters[0].raddr = addr("::ffff:203.0.113.9");
	a->filters[0].prefix = 128;
	lease_table_link(a);
	assert(lease_table_changes(LEASE_T_FILTERS) == flt + 1);
	/* a renewal or a label changes no filter line */
	lease_table_set_expiry(a, 200);
	assert(lease_table_set_label(a, "z") == 0);
	assert(lease_table_changes(LEASE_T_FILTERS) == flt + 1);
	lease_table_remove(a);
	assert(lease_table_changes(LEASE_T_FILTERS) == flt + 2);
	lease_table_clear();
}

/* The filters of a linked row: added and dropped in place, with their uids
 * in the UID index wherever the array moves. */
static void
test_linked_filters(void)
{
	struct map_filter nf, * f, * g;
	struct lease_entry * m6;
	int i;
	lease_table_clear();
	m6 = add6(MAP_KIND_UPNP, "2001:db8::10", 41010, 21);
	assert(lease_table_filter_count() == 1);
	memset(&nf, 0, sizeof(nf));
	nf.raddr = addr("2001:db8:1::5");
	nf.prefix = 128;
	/* enough adds to move the array several times */
	for(i = 0; i < 40; i++) {
		nf.rport = (unsigned short)(1000 + i);
		nf.uid = (unsigned short)(100 + i);
		f = lease_filter_add(m6, &nf);
		assert(f != NULL && f->map == m6 && f->uid == 100 + i);
	}
	assert(m6->nfilters == 41 && lease_table_filter_count() == 41);
	for(i = 0; i < 40; i++) {
		f = lease_table_find_uid((unsigned short)(100 + i));
		assert(f == &m6->filters[i + 1] && f->rport == 1000 + i);
	}
	assert(lease_table_find_uid(21) == &m6->filters[0]);
	assert(lease_filter_find(m6, &nf.raddr, 128, 1005) == &m6->filters[6]);
	assert(lease_filter_find(m6, &nf.raddr, 64, 1005) == NULL);
	/* a drop: its uid goes, the ones after it are found where they moved */
	g = lease_table_find_uid(110);
	lease_filter_drop(m6, g);
	assert(lease_table_find_uid(110) == NULL && m6->nfilters == 40);
	assert(lease_table_filter_count() == 40);
	for(i = 11; i < 40; i++)
		assert(lease_table_find_uid((unsigned short)(100 + i)) == &m6->filters[i]);
	/* a uid given later, and changed */
	f = &m6->filters[5];
	lease_filter_set_uid(f, 500);
	assert(lease_table_find_uid(500) == f && lease_table_find_uid(104) == NULL);
	/* a filter of an unlinked row is in no index until the link */
	{
		struct lease_entry * s = lease_table_new(1);
		assert(s != NULL);
		s->family = AF_INET6;
		s->proto = IPPROTO_TCP;
		s->iaddr = s->eaddr = addr("2001:db8::11");
		s->iport = s->eport = 7;
		lease_filter_set_uid(&s->filters[0], 600);
		nf.uid = 601;
		assert(lease_filter_add(s, &nf) != NULL);
		assert(lease_table_find_uid(600) == NULL && lease_table_find_uid(601) == NULL);
		lease_table_link(s);
		assert(lease_table_find_uid(600) == &s->filters[0]);
		assert(lease_table_find_uid(601) == &s->filters[1]);
	}
	lease_table_remove(m6);
	assert(lease_table_find_uid(21) == NULL && lease_table_find_uid(500) == NULL);
	assert(lease_table_filter_count() == 2);
	lease_table_clear();
	assert(lease_table_filter_count() == 0);
}

/* A row in the place of another: the uids of its filters, also the same ones,
 * name the new row. */
static void
test_in_place_uid(void)
{
	struct lease_entry * old, * e;
	lease_table_clear();
	old = add6(MAP_KIND_UPNP, "2001:db8::10", 41000, 7);
	e = lease_table_new(1);
	assert(e != NULL);
	e->kind = MAP_KIND_UPNP;
	e->family = AF_INET6;
	e->proto = IPPROTO_UDP;
	e->iaddr = e->eaddr = old->iaddr;
	e->iport = e->eport = old->iport;
	e->filters[0].uid = 7;
	lease_table_link_in_place(e, old);
	assert(lease_table_find_uid(7) == &e->filters[0]);
	assert(lease_table_count() == 1);
	lease_table_clear();
}

/* The dump: a header, a line per row, the IPv4 ones in list order, and a
 * line per filter. */
static void
test_dump(void)
{
	char path[] = "/tmp/testleasetable.XXXXXX";
	char line[512];
	struct lease_entry * e;
	FILE * f;
	int fd, n = 0;

	lease_table_clear();
	e = newrow(MAP_KIND_PCP, IPPROTO_UDP, 40001, "::ffff:192.0.2.10", 8080, 1, 1);
	e->filters[0].raddr = addr("::ffff:203.0.113.5");
	e->filters[0].prefix = 128;
	lease_table_set_expiry(e, 1234);
	lease_table_link(e);
	e = add(MAP_KIND_UPNP, IPPROTO_TCP, 40002, "::ffff:192.0.2.11", 22, 0);
	assert(lease_table_set_label(e, "ssh") == 0);
	add6(MAP_KIND_UPNP, "2001:db8::10", 41000, 7);
	fd = mkstemp(path);
	assert(fd >= 0);
	f = fdopen(fd, "w+");
	assert(f != NULL);
	lease_table_dump(f);
	rewind(f);
	assert(f != NULL);
	while(fgets(line, sizeof(line), f) != NULL) {
		switch(n++) {
		case 0:
			assert(strstr(line, "# lease table: 3 rows, 2 port mappings, 2 filters, 1 uids, last id ") == line);
			break;
		case 1:
			assert(strstr(line, "PCP IPv4 UDP [192.0.2.10]:8080 <- [0.0.0.0]:40001 expiry=1234") != NULL);
			assert(strstr(line, "nonce=000000000000000000000001") != NULL);
			break;
		case 2:
			assert(strcmp(line, "\tfilter [::ffff:203.0.113.5]/128:0 uid=0\n") == 0);
			break;
		case 3:
			assert(strstr(line, "UPnP IPv4 TCP [192.0.2.11]:22 <- [0.0.0.0]:40002") != NULL);
			assert(strstr(line, "label=\"ssh\"") != NULL);
			break;
		case 4:
			assert(strstr(line, "UPnP IPv6 UDP [2001:db8::10]:41000 <- [2001:db8::10]:41000") != NULL);
			break;
		case 5:
			assert(strcmp(line, "\tfilter [::]/0:0 uid=7\n") == 0);
			break;
		}
	}
	fclose(f);
	unlink(path);
	assert(n == 6);
	lease_table_clear();
}

int
main(void)
{
	static const char * h1 = "::ffff:192.0.2.10", * h2 = "::ffff:192.0.2.11";
	static const char game[] = "a game";
	static const struct in6_addr any_addr;
	struct in6_addr remote = addr("::ffff:203.0.113.5");
	struct in6_addr second = addr("::ffff:198.51.100.2");
	struct lease_entry * m, * p, * x, * pin, * u;
	unsigned int i, n = 0;

	test_new_uid();
	test_uids_full();
	test_pcp_no_uid();
	test_ids();
	test_changes();
	test_linked_filters();
	test_in_place_uid();
	test_dump();

	/* the key : proto, eaddr, eport */
	lease_table_clear();
	m = newrow(MAP_KIND_PCP, 17, 40001, h1, 8080, 1, 0);
	/* the label is the caller's until the link, which takes a copy */
	m->label = game;
	lease_table_link(m);
	assert(m->label != game && strcmp(m->label, "a game") == 0 && m->nonce[11] == 1);
	assert(lease_table_find_mapping(17, AF_INET, &any_addr, 40001) == m);
	assert(lease_table_find_mapping(6, AF_INET, &any_addr, 40001) == NULL);
	assert(lease_table_find_mapping(17, AF_INET, &any_addr, 40002) == NULL);
	/* another external address of the interface : a mapping of its own */
	x = newrow(MAP_KIND_PCP, 17, 40001, h1, 8080, 1, 0);
	x->eaddr = second;
	lease_table_link(x);
	assert(lease_table_find_mapping(17, AF_INET, &second, 40001) == x);
	lease_table_remove(x);
	assert(lease_table_find_mapping(17, AF_INET, &second, 40001) == NULL);
	assert(lease_table_count() == 1);

	/* the companion port : any protocol, another host only */
	{
		struct in6_addr a1 = addr(h1), a2 = addr(h2);
		assert(lease_table_port_used_by_other(AF_INET, &any_addr, 40001, &a2) == m);
		assert(lease_table_port_used_by_other(AF_INET, &any_addr, 40001, &a1) == NULL);
		assert(lease_table_port_used_by_other(AF_INET, &any_addr, 40009, &a2) == NULL);
	}

	/* a mapping limited to a remote host: a filter of the row; the key has
	 * no remote */
	p = newrow(MAP_KIND_UPNP, 6, 40003, h2, 9000, 0, 1);
	p->filters[0].raddr = remote;
	p->filters[0].prefix = 128;
	lease_table_link(p);
	assert(p->nfilters == 1 && p->filters[0].map == p);
	assert(lease_filter_find(p, &remote, 128, 0) != NULL &&
	       lease_filter_find(p, &remote, 128, 80) == NULL);
	assert(lease_table_find_mapping(6, AF_INET, &any_addr, 40003) == p);

	/* an IPv6 map of UPnP by its uid; one of PCP has none */
	pin = add6(MAP_KIND_UPNP, "2001:db8::10", 41000, 7);
	assert(lease_table_find_uid(7) == &pin->filters[0]);
	assert(lease_table_find_uid(7)->map == pin);
	assert(lease_table_find_uid(8) == NULL && lease_table_find_uid(0) == NULL);
	x = add6(MAP_KIND_PCP, "2001:db8::10", 41001, 0);
	assert(lease_table_find_uid(7) == &pin->filters[0]);
	/* a UPnP client takes the PCP IPv6 map over: its filter gets a uid */
	lease_filter_set_uid(&x->filters[0], 8);
	assert(lease_table_find_uid(8) == &x->filters[0]);
	lease_table_remove(x);
	lease_table_remove(pin);
	assert(lease_table_find_uid(7) == NULL && lease_table_find_uid(8) == NULL);

	/* a row in the place of another, on the same key or on a new one */
	n = lease_table_count();
	x = newrow(MAP_KIND_NATPMP, 6, 40003, h1, 9100, 0, 0);
	lease_table_link_in_place(x, p);
	assert(lease_table_count() == n);
	assert(lease_table_find_mapping(6, AF_INET, &any_addr, 40003) == x && x->nfilters == 0);
	assert(x->kind == MAP_KIND_NATPMP && x->iport == 9100);
	p = newrow(MAP_KIND_NATPMP, 6, 40004, h1, 9100, 0, 0);
	lease_table_link_in_place(p, x);
	assert(lease_table_count() == n);
	assert(lease_table_find_mapping(6, AF_INET, &any_addr, 40003) == NULL);
	assert(lease_table_find_mapping(6, AF_INET, &any_addr, 40004) == p);
	assert(lease_table_find_mapping(17, AF_INET, &any_addr, 40001) == m);
	n = 0;

	/* many rows on an internal port */
	{
		struct in6_addr a2 = addr(h2);
		lease_table_clear();
		add(MAP_KIND_UPNP, 17, 40002, h2, 9000, 0);
		x = add(MAP_KIND_UPNP, 17, 40003, h2, 9000, 0);
		add(MAP_KIND_UPNP, 6, 40004, h2, 9000, 0);
		for(p = lease_table_next_internal(NULL, 17, AF_INET, &a2, 9000); p != NULL;
		    p = lease_table_next_internal(p, 17, AF_INET, &a2, 9000))
			n++;
		assert(n == 2);
		/* the row of the endpoint on an external port */
		assert(lease_table_find_entry(17, AF_INET, &a2, 9000, 40003) == x);
		assert(lease_table_find_entry(17, AF_INET, &a2, 9000, 40004) == NULL);
		assert(lease_table_find_entry(6, AF_INET, &a2, 9000, 40004) != NULL);
		lease_table_remove(x);
		assert(lease_table_find_entry(17, AF_INET, &a2, 9000, 40003) == NULL);
		assert(lease_table_next_internal(NULL, 17, AF_INET, &a2, 9000)->eport == 40002);
		n = 0;
	}

	/* a label can change. The owner is kind, family, proto, iaddr, iport and
	 * nonce; the eport is no part of it */
	lease_table_clear();
	m = add(MAP_KIND_UPNP, 17, 40001, h1, 8080, 0);
	u = add(MAP_KIND_UPNP, 17, 40002, h1, 8080, 0);
	assert(lease_table_same_owner(m, u));
	assert(lease_table_set_label(m, "ssh") == 0 && strcmp(m->label, "ssh") == 0);
	/* the same label again, also its own: replaced, never compared */
	assert(lease_table_set_label(m, "ssh") == 0 && strcmp(m->label, "ssh") == 0);
	assert(lease_table_set_label(m, m->label) == 0 && strcmp(m->label, "ssh") == 0);
	assert(lease_table_set_label(m, NULL) == 0 && m->label == NULL);
	assert(lease_table_set_label(m, NULL) == 0 && m->label == NULL);
	p = add(MAP_KIND_PCP, 17, 40003, h1, 8080, 0);
	assert(!lease_table_same_owner(p, u));	/* a zero nonce is not UPnP */
	x = add(MAP_KIND_PCP, 17, 40004, h1, 8080, 7);
	assert(!lease_table_same_owner(p, x));
	assert(!lease_table_same_owner(add(MAP_KIND_NATPMP, 17, 40005, h1, 8080, 0), u));
	/* the same kind on another part of the key: another owner */
	assert(!lease_table_same_owner(add(MAP_KIND_UPNP, 17, 40006, h2, 8080, 0), u));
	assert(!lease_table_same_owner(add(MAP_KIND_UPNP, 17, 40007, h1, 8081, 0), u));
	assert(!lease_table_same_owner(add(MAP_KIND_UPNP, 6, 40008, h1, 8080, 0), u));

	/* the port mappings : oldest first, without an IPv6 map */
	lease_table_clear();
	assert(lease_table_port_count() == 0 && lease_table_port_at(0) == NULL);
	m = add(MAP_KIND_UPNP, 17, 40001, h1, 8080, 0);
	pin = add6(MAP_KIND_UPNP, "2001:db8::10", 41000, 0);
	u = add(MAP_KIND_NATPMP, 17, 40002, h1, 8081, 0);
	x = add(MAP_KIND_PCP, 6, 40003, h1, 8082, 2);
	assert(lease_table_port_count() == 3 && lease_table_count() == 4);
	assert(lease_table_port_at(0) == m && lease_table_port_at(1) == u);
	assert(lease_table_port_at(2) == x && lease_table_port_at(3) == NULL);
	assert(lease_table_next_port(NULL) == m && lease_table_next_port(m) == u);
	assert(lease_table_next_port(x) == NULL);
	/* backwards, and an add while a client reads */
	assert(lease_table_port_at(0) == m);
	assert(lease_table_port_at(1) == u);
	add(MAP_KIND_UPNP, 17, 40004, h2, 9000, 0);
	assert(lease_table_port_at(2) == x);
	assert(lease_table_port_at(3) != NULL && lease_table_port_at(3)->eport == 40004);
	/* a row in the place of another keeps its place */
	p = newrow(MAP_KIND_NATPMP, 17, 40002, h1, 8090, 0, 0);
	lease_table_link_in_place(p, u);
	u = p;
	assert(lease_table_port_at(1) == u && lease_table_port_at(2) == x);
	/* a remove : the row under the cursor, the first and the last. An IPv6
	 * map does not count */
	assert(lease_table_port_at(1) == u);
	lease_table_remove(u);
	assert(lease_table_port_count() == 3);
	assert(lease_table_port_at(1) == x);
	lease_table_remove(pin);
	assert(lease_table_port_count() == 3 && lease_table_port_at(1) == x);
	lease_table_remove(m);
	assert(lease_table_port_at(0) == x);
	lease_table_remove(lease_table_port_at(1));
	assert(lease_table_port_count() == 1 && lease_table_next_port(x) == NULL);
	lease_table_remove(x);
	assert(lease_table_next_port(NULL) == NULL && lease_table_port_at(0) == NULL);

	/* growth keeps every row, and their order */
	lease_table_clear();
	assert(lease_table_count() == 0);
	assert(lease_table_find_mapping(17, AF_INET, &any_addr, 40001) == NULL);
	for(i = 1; i <= 20000; i++)
		add(MAP_KIND_UPNP, 17, (unsigned short)i, h1, (unsigned short)(i % 7 + 1), 0);
	lease_table_foreach(counter, &n);
	assert(n == 20000 && lease_table_count() == 20000);
	assert(lease_table_port_count() == 20000);
	for(i = 0; i < 20000; i++)
		assert(lease_table_port_at(i)->eport == i + 1);
	for(i = 1; i <= 20000; i++)
		assert(lease_table_find_mapping(17, AF_INET, &any_addr, (unsigned short)i) != NULL);
	n = 0;
	{
		struct in6_addr a1 = addr(h1);
		for(p = lease_table_next_internal(NULL, 17, AF_INET, &a1, 1); p != NULL;
		    p = lease_table_next_internal(p, 17, AF_INET, &a1, 1))
			n++;
	}
	assert(n == 2857);
	lease_table_clear();

	printf("testleasetable: OK\n");
	return 0;
}
