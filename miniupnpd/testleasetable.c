/* unit test of lease_table.c */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "lease_table.h"

static struct in6_addr
addr(const char * s)
{
	struct in6_addr a;
	assert(inet_pton(AF_INET6, s, &a) == 1);
	return a;
}

static struct lease_entry
row(int kind, int proto, unsigned short eport, const char * iaddr,
    unsigned short iport, unsigned char nonce)
{
	struct lease_entry e;
	memset(&e, 0, sizeof(e));
	e.kind = kind;
	e.family = AF_INET;
	e.proto = proto;
	e.eport = eport;
	e.iport = iport;
	e.iaddr = addr(iaddr);
	e.nonce[11] = nonce;
	return e;
}

static void
counter(struct lease_entry * e, void * arg)
{
	(void)e;
	(*(unsigned int *)arg)++;
}

int
main(void)
{
	static const char * h1 = "::ffff:192.0.2.10", * h2 = "::ffff:192.0.2.11";
	struct in6_addr remote = addr("::ffff:203.0.113.5");
	struct in6_addr second = addr("::ffff:198.51.100.2");
	struct lease_entry e, * m, * p, * x, * pin, * u;
	unsigned int i, n = 0;

	/* the key : proto, eaddr, eport */
	e = row(LEASE_PCP_MAP, 17, 40001, h1, 8080, 1);
	e.label = "PCP MAP";
	m = lease_table_add(&e, NULL, 0);
	assert(m != NULL);
	assert(m->label != e.label && strcmp(m->label, "PCP MAP") == 0);
	assert(m->nonce[11] == 1);
	assert(lease_table_add(&e, NULL, 0) == NULL);
	assert(lease_table_find_external(17, AF_INET, NULL, 40001, NULL, 0) == m);
	assert(lease_table_find_external(6, AF_INET, NULL, 40001, NULL, 0) == NULL);
	assert(lease_table_find_mapping(17, AF_INET, NULL, 40001) == m);
	assert(lease_table_find_mapping(17, AF_INET, NULL, 40002) == NULL);
	/* another external address of the interface : a mapping of its own */
	e.eaddr = second;
	x = lease_table_add(&e, NULL, 0);
	assert(x != NULL && x != m);
	assert(lease_table_find_external(17, AF_INET, &second, 40001, NULL, 0) == x);
	assert(lease_table_find_mapping(17, AF_INET, &second, 40001) == x);
	lease_table_remove(x);
	assert(lease_table_find_mapping(17, AF_INET, &second, 40001) == NULL);
	assert(lease_table_count() == 1);

	/* a mapping limited to a remote host */
	e = row(LEASE_UPNP, 6, 40003, h2, 9000, 0);
	p = lease_table_add(&e, &remote, 0);
	assert(p != NULL && p->remote != NULL);
	assert(lease_table_find_external(6, AF_INET, NULL, 40003, &remote, 0) == p);
	assert(lease_table_find_external(6, AF_INET, NULL, 40003, NULL, 0) == NULL);
	assert(lease_table_find_mapping(6, AF_INET, NULL, 40003) == p);

	/* a pinhole, by its UniqueID. A PCP nonce is not one */
	e = row(LEASE_UPNP, 6, 41000, "2001:db8::10", 41000, 0);
	e.family = AF_INET6;
	lease_set_uid(&e, 7);
	e.eaddr = e.iaddr;
	pin = lease_table_add(&e, NULL, 0);
	assert(lease_table_find_uid(7) == pin && lease_table_find_uid(8) == NULL);
	e.kind = LEASE_PCP_MAP;
	e.eport = e.iport = 41001;
	x = lease_table_add(&e, NULL, 0);
	assert(x != NULL && lease_uid(x) == 0 && lease_table_find_uid(7) == pin);
	lease_table_remove(x);
	lease_table_remove(pin);
	assert(lease_table_find_uid(7) == NULL);

	/* replace : on the same key, or on a new one */
	n = lease_table_count();
	e = row(LEASE_NATPMP, 6, 40003, h1, 9100, 0);
	e.label = "NAT-PMP";
	x = lease_table_replace(p, &e, &remote, 0);
	assert(x != NULL && lease_table_count() == n);
	assert(lease_table_find_external(6, AF_INET, NULL, 40003, &remote, 0) == x);
	assert(x->kind == LEASE_NATPMP && x->iport == 9100 && strcmp(x->label, "NAT-PMP") == 0);
	p = lease_table_replace(x, &e, NULL, 0);
	assert(p != NULL && lease_table_count() == n);
	assert(lease_table_find_external(6, AF_INET, NULL, 40003, &remote, 0) == NULL);
	assert(lease_table_find_external(6, AF_INET, NULL, 40003, NULL, 0) == p);
	/* not on the key of another row : both stay */
	e = row(LEASE_UPNP, 17, 40001, h2, 9200, 0);
	assert(lease_table_replace(p, &e, NULL, 0) == NULL);
	assert(lease_table_find_external(6, AF_INET, NULL, 40003, NULL, 0) == p);
	assert(lease_table_find_external(17, AF_INET, NULL, 40001, NULL, 0) == m);
	assert(lease_table_count() == n);
	/* a uid moves with its row */
	e = row(LEASE_UPNP, 6, 41000, "2001:db8::10", 41000, 0);
	e.family = AF_INET6;
	e.eaddr = e.iaddr;
	lease_set_uid(&e, 7);
	pin = lease_table_add(&e, NULL, 0);
	lease_set_uid(&e, 9);
	x = lease_table_replace(pin, &e, NULL, 0);
	assert(x != NULL && lease_table_find_uid(9) == x && lease_table_find_uid(7) == NULL);
	lease_table_remove(x);
	n = 0;

	/* many rows on an internal port */
	{
		struct in6_addr a2 = addr(h2);
		lease_table_clear();
		e = row(LEASE_UPNP, 17, 40002, h2, 9000, 0);
		assert(lease_table_add(&e, NULL, 0) != NULL);
		e.eport = 40003;
		x = lease_table_add(&e, NULL, 0);
		assert(x != NULL);
		e.proto = 6;
		e.eport = 40004;
		assert(lease_table_add(&e, NULL, 0) != NULL);
		n = 0;
		for(p = lease_table_next_internal(NULL, 17, AF_INET, &a2, 9000); p != NULL;
		    p = lease_table_next_internal(p, 17, AF_INET, &a2, 9000))
			n++;
		assert(n == 2);
		lease_table_remove(x);
		assert(lease_table_next_internal(NULL, 17, AF_INET, &a2, 9000)->eport == 40002);
		n = 0;
	}

	/* a label can change, and an owner is its kind and nonce */
	lease_table_clear();
	e = row(LEASE_UPNP, 17, 40001, h1, 8080, 0);
	m = lease_table_add(&e, NULL, 0);
	e.eport = 40002;
	u = lease_table_add(&e, NULL, 0);
	assert(lease_table_same_owner(m, u));
	assert(lease_table_set_label(m, "ssh") == 0 && strcmp(m->label, "ssh") == 0);
	assert(lease_table_set_label(m, NULL) == 0 && m->label == NULL);
	e = row(LEASE_PCP_MAP, 17, 40003, h1, 8080, 0);
	p = lease_table_add(&e, NULL, 0);
	assert(!lease_table_same_owner(p, u));	/* a zero nonce is not UPnP */
	e = row(LEASE_PCP_MAP, 17, 40004, h1, 8080, 7);
	x = lease_table_add(&e, NULL, 0);
	assert(!lease_table_same_owner(p, x));
	e = row(LEASE_NATPMP, 17, 40005, h1, 8080, 0);
	assert(!lease_table_same_owner(lease_table_add(&e, NULL, 0), u));

	/* the port mappings : oldest first, without a pinhole */
	lease_table_clear();
	assert(lease_table_port_count() == 0 && lease_table_port_at(0) == NULL);
	e = row(LEASE_UPNP, 17, 40001, h1, 8080, 0);
	m = lease_table_add(&e, NULL, 0);
	e = row(LEASE_UPNP, 6, 41000, "2001:db8::10", 41000, 0);
	e.family = AF_INET6;
	pin = lease_table_add(&e, NULL, 0);
	e = row(LEASE_NATPMP, 17, 40002, h1, 8081, 0);
	u = lease_table_add(&e, NULL, 0);
	e = row(LEASE_PCP_MAP, 6, 40003, h1, 8082, 2);
	x = lease_table_add(&e, NULL, 0);
	assert(lease_table_port_count() == 3 && lease_table_count() == 4);
	assert(lease_table_port_at(0) == m && lease_table_port_at(1) == u);
	assert(lease_table_port_at(2) == x && lease_table_port_at(3) == NULL);
	assert(lease_table_next_port(NULL) == m && lease_table_next_port(m) == u);
	assert(lease_table_next_port(x) == NULL);
	/* backwards, and an add while a client reads */
	assert(lease_table_port_at(0) == m);
	assert(lease_table_port_at(1) == u);
	e = row(LEASE_UPNP, 17, 40004, h2, 9000, 0);
	assert(lease_table_add(&e, NULL, 0) != NULL);
	assert(lease_table_port_at(2) == x);
	assert(lease_table_port_at(3) != NULL && lease_table_port_at(3)->eport == 40004);
	/* a remove : the row under the cursor, the first and the last. A pinhole
	 * does not count */
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
	assert(lease_table_find_mapping(17, AF_INET, NULL, 40001) == NULL);
	for(i = 1; i <= 20000; i++) {
		e = row(LEASE_UPNP, 17, (unsigned short)i, h1, (unsigned short)(i % 7 + 1), 0);
		assert(lease_table_add(&e, NULL, 0) != NULL);
	}
	lease_table_foreach(counter, &n);
	assert(n == 20000 && lease_table_count() == 20000);
	assert(lease_table_port_count() == 20000);
	for(i = 0; i < 20000; i++)
		assert(lease_table_port_at(i)->eport == i + 1);
	for(i = 1; i <= 20000; i++)
		assert(lease_table_find_external(17, AF_INET, NULL, (unsigned short)i, NULL, 0) != NULL);
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
