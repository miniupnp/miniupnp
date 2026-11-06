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
	struct lease_entry e, * m, * p, * x, * pin;
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

	/* growth keeps every row */
	lease_table_clear();
	assert(lease_table_count() == 0);
	assert(lease_table_find_mapping(17, AF_INET, NULL, 40001) == NULL);
	for(i = 1; i <= 20000; i++) {
		e = row(LEASE_UPNP, 17, (unsigned short)i, h1, (unsigned short)(i % 7 + 1), 0);
		assert(lease_table_add(&e, NULL, 0) != NULL);
	}
	lease_table_foreach(counter, &n);
	assert(n == 20000 && lease_table_count() == 20000);
	for(i = 1; i <= 20000; i++)
		assert(lease_table_find_external(17, AF_INET, NULL, (unsigned short)i, NULL, 0) != NULL);
	lease_table_clear();

	printf("testleasetable: OK\n");
	return 0;
}
