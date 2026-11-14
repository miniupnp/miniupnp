/* unit test of memmap.c : the rows it writes for the firewall rules */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "config.h"
#include "upnpredirect.h"
#include "lease_table.h"
#include "memmap.h"

/* The owner of a rule, as upnpredirect.c reads it from the description, without
 * the rest of that file. */
enum mapping_owner
mapping_owner_of(const char * desc, unsigned short eport, int proto)
{
	size_t n;
	(void)eport;
	(void)proto;
	if(desc == NULL)
		return MAPPING_UPNP;
	n = strlen(desc);
	if(strncmp(desc, "PCP MAP ", 8) == 0 && n >= 8 + 24 &&
	   strspn(desc + n - 24, "0123456789abcdefABCDEF") == 24)
		return MAPPING_PCP;
	if(strncmp(desc, "NAT-PMP ", 8) == 0)
		return MAPPING_NATPMP;
	return MAPPING_UPNP;
}

#define PCP_DESC	"PCP MAP 0102030405060708090a0b0c"

static struct in6_addr
addr(const char * s)
{
	struct in6_addr a;
	assert(inet_pton(AF_INET6, s, &a) == 1);
	return a;
}

static int
same_addr(const struct in6_addr * a, const char * s)
{
	struct in6_addr b = addr(s);
	return memcmp(a, &b, sizeof(b)) == 0;
}

/* an IPv6 pinhole by its key */
static struct lease_entry *
pinhole(const char * iaddr, unsigned short iport, const char * raddr,
        unsigned short rport)
{
	struct in6_addr i = addr(iaddr), r;
	if(raddr != NULL)
		r = addr(raddr);
	return lease_table_find_external(IPPROTO_UDP, AF_INET6, &i, iport,
	                                 raddr ? &r : NULL, rport);
}

static void
test_ipv4(void)
{
	struct lease_entry * row, * again;
	struct in6_addr r = addr("::ffff:203.0.113.5");

	lease_table_clear();
	/* add */
	memmap_map(0, 40001, "192.0.2.10", 8080, IPPROTO_TCP, "web", 100);
	row = lease_table_find_mapping(IPPROTO_TCP, AF_INET, NULL, 40001);
	assert(row != NULL && lease_table_count() == 1);
	assert(row->kind == LEASE_UPNP && lease_uid(row) == 0);
	assert(same_addr(&row->iaddr, "::ffff:192.0.2.10") && row->iport == 8080);
	assert(row->expiry == 100 && strcmp(row->label, "web") == 0);
	assert(row->remote == NULL);

	/* renew : one row, with the new expiry and label */
	memmap_map(0, 40001, "192.0.2.10", 8080, IPPROTO_TCP, "web2", 200);
	row = lease_table_find_mapping(IPPROTO_TCP, AF_INET, NULL, 40001);
	assert(row != NULL && lease_table_count() == 1);
	assert(row->expiry == 200 && strcmp(row->label, "web2") == 0);

	/* the same key for another client and owner : the row is replaced */
	memmap_map(0, 40001, "192.0.2.11", 9090, IPPROTO_TCP, "NAT-PMP 40001 tcp", 300);
	again = lease_table_find_mapping(IPPROTO_TCP, AF_INET, NULL, 40001);
	assert(again != NULL && lease_table_count() == 1);
	assert(again->kind == LEASE_NATPMP);
	assert(same_addr(&again->iaddr, "::ffff:192.0.2.11") && again->iport == 9090);
	assert(again->expiry == 300 && strcmp(again->label, "NAT-PMP 40001 tcp") == 0);

	/* a PCP owner : the nonce from the description */
	memmap_map(0, 40001, "192.0.2.11", 9090, IPPROTO_TCP, PCP_DESC, 300);
	row = lease_table_find_mapping(IPPROTO_TCP, AF_INET, NULL, 40001);
	assert(row->kind == LEASE_PCP_MAP && lease_uid(row) == 0);
	assert(row->nonce[0] == 0x01 && row->nonce[11] == 0x0c);

	/* no label */
	memmap_map(0, 40001, "192.0.2.11", 9090, IPPROTO_TCP, NULL, 300);
	row = lease_table_find_mapping(IPPROTO_TCP, AF_INET, NULL, 40001);
	assert(row != NULL && row->label == NULL && row->kind == LEASE_UPNP);

	/* a remote : the row with no remote is replaced by one with it */
	memmap_remote_peer(0, "203.0.113.5", 5000, 40001, "192.0.2.10", 8080,
	                   IPPROTO_TCP, "peer", 400);
	assert(lease_table_count() == 1);
	row = lease_table_find_external(IPPROTO_TCP, AF_INET, NULL, 40001, &r, 5000);
	assert(row != NULL && row->remote != NULL && row->expiry == 400);
	assert(lease_table_find_external(IPPROTO_TCP, AF_INET, NULL, 40001, NULL, 0) == NULL);
	/* and renewed with the same remote */
	memmap_remote_peer(0, "203.0.113.5", 5000, 40001, "192.0.2.10", 8080,
	                   IPPROTO_TCP, "peer", 500);
	again = lease_table_find_external(IPPROTO_TCP, AF_INET, NULL, 40001, &r, 5000);
	assert(again != NULL && again->expiry == 500 && lease_table_count() == 1);
	/* and back to no remote */
	memmap_map(0, 40001, "192.0.2.10", 8080, IPPROTO_TCP, "web", 600);
	assert(lease_table_count() == 1);
	row = lease_table_find_external(IPPROTO_TCP, AF_INET, NULL, 40001, NULL, 0);
	assert(row != NULL && row->expiry == 600);

	/* other protocol, other row */
	memmap_map(0, 40001, "192.0.2.10", 8080, IPPROTO_UDP, "web", 600);
	assert(lease_table_count() == 2);
	memmap_map_gone(40001, IPPROTO_TCP);
	assert(lease_table_find_mapping(IPPROTO_TCP, AF_INET, NULL, 40001) == NULL);
	assert(lease_table_find_mapping(IPPROTO_UDP, AF_INET, NULL, 40001) != NULL);
	memmap_map_gone(40001, IPPROTO_TCP);	/* no row : nothing */
	assert(lease_table_count() == 1);

	/* an address which is not IPv4 or IPv6 : no row */
	memmap_map(0, 40002, "not an address", 8080, IPPROTO_TCP, "web", 600);
	assert(lease_table_count() == 1);
}

static void
test_ipv6(void)
{
	static const char * h = "2001:db8::10", * peer = "2001:db8:1::5";
	struct lease_entry * row, * again;

	lease_table_clear();
	/* a UPnP pinhole : found by its uid */
	memmap_map(7, 0, h, 8080, IPPROTO_UDP, "upnp", 100);
	row = lease_table_find_uid(7);
	assert(row != NULL && row == pinhole(h, 8080, NULL, 0));
	assert(row->family == AF_INET6 && row->eport == 8080 && row->iport == 8080);
	assert(same_addr(&row->eaddr, h) && same_addr(&row->iaddr, h));
	assert(row->kind == LEASE_UPNP && lease_uid(row) == 7);

	/* renew by uid, without a description */
	memmap_map(7, 0, h, 8080, IPPROTO_UDP, NULL, 200);
	assert(lease_table_find_uid(7) == row && row->expiry == 200);
	memmap_renew_uid(7, 300);
	assert(row->expiry == 300 && strcmp(row->label, "upnp") == 0);
	memmap_renew_uid(8, 999);	/* no row : nothing */
	assert(lease_table_count() == 1);

	/* renew with the same description : the row stays */
	memmap_map(7, 0, h, 8080, IPPROTO_UDP, "upnp", 400);
	assert(lease_table_find_uid(7) == row && row->expiry == 400);

	/* another description on the key : a new row */
	memmap_map(7, 0, h, 8080, IPPROTO_UDP, "other", 500);
	again = lease_table_find_uid(7);
	assert(again != NULL && strcmp(again->label, "other") == 0);
	assert(again->expiry == 500 && lease_table_count() == 1);

	/* a pinhole with a remote : its own row next to the one without */
	memmap_remote_peer(9, peer, 5000, 0, h, 8080, IPPROTO_UDP, "upnp peer", 600);
	assert(lease_table_count() == 2);
	row = lease_table_find_uid(9);
	assert(row != NULL && row == pinhole(h, 8080, peer, 5000));
	assert(row->remote != NULL && row->remote->rport == 5000);
	memmap_remote_peer_gone(9);
	assert(lease_table_find_uid(9) == NULL && lease_table_count() == 1);
	memmap_remote_peer_gone(9);	/* no row : nothing */
	assert(lease_table_count() == 1);

	/* PCP has no uid : the row is found by its key */
	memmap_remote_peer(0, peer, 5000, 0, h, 9090, IPPROTO_UDP, PCP_DESC, 700);
	row = pinhole(h, 9090, peer, 5000);
	assert(row != NULL && row->kind == LEASE_PCP_MAP && lease_uid(row) == 0);
	assert(lease_table_count() == 2);
	/* a renewal by the key keeps the row */
	memmap_remote_peer(0, peer, 5000, 0, h, 9090, IPPROTO_UDP, PCP_DESC, 800);
	assert(pinhole(h, 9090, peer, 5000) == row && row->expiry == 800);
	/* the firewall gives the remote of a rule : the row goes */
	memmap_remote_peer_gone_at(0, peer, 5000, h, 9090, IPPROTO_UDP);
	assert(pinhole(h, 9090, peer, 5000) == NULL && lease_table_count() == 1);

	/* a PCP MAP pinhole has no remote, and the firewall gives :: for it */
	memmap_map(0, 0, h, 9091, IPPROTO_UDP, PCP_DESC, 900);
	assert(pinhole(h, 9091, NULL, 0) != NULL && lease_table_count() == 2);
	memmap_remote_peer_gone_at(0, "::", 0, h, 9091, IPPROTO_UDP);
	assert(pinhole(h, 9091, NULL, 0) == NULL && lease_table_count() == 1);

	/* gone_at with a uid takes the row of the uid */
	memmap_remote_peer_gone_at(7, NULL, 0, h, 1, IPPROTO_UDP);
	assert(lease_table_find_uid(7) == NULL && lease_table_count() == 0);

	/* a bad internal address : no row */
	memmap_map(3, 0, "2001:db8::zz", 8080, IPPROTO_UDP, "upnp", 100);
	assert(lease_table_count() == 0);
}

static void
test_expiry(void)
{
	char iaddr[64];
	unsigned int i;

	lease_table_clear();
	/* more expired pinholes than one walk takes */
	for(i = 0; i < 600; i++) {
		snprintf(iaddr, sizeof(iaddr), "2001:db8::%x", i + 1);
		memmap_map((unsigned short)(i + 1), 0, iaddr, 8080, IPPROTO_UDP, "upnp", 100);
	}
	memmap_map(1000, 0, "2001:db8:1::1", 8080, IPPROTO_UDP, "upnp", 101);
	memmap_map(1001, 0, "2001:db8:1::2", 8080, IPPROTO_UDP, "upnp", 0);
	/* an IPv4 mapping is not a pinhole, whatever its expiry */
	memmap_map(0, 40001, "192.0.2.10", 8080, IPPROTO_TCP, "web", 50);
	assert(lease_table_count() == 603);

	memmap_remote_peers_expired(99);
	assert(lease_table_count() == 603);
	memmap_remote_peers_expired(100);
	assert(lease_table_count() == 3);
	assert(lease_table_find_uid(1) == NULL && lease_table_find_uid(600) == NULL);
	assert(lease_table_find_uid(1000) != NULL);
	memmap_remote_peers_expired(101);
	assert(lease_table_find_uid(1000) == NULL);
	/* 0 : no expiry */
	memmap_remote_peers_expired(0xffffffffu);
	assert(lease_table_find_uid(1001) != NULL);
	assert(lease_table_find_mapping(IPPROTO_TCP, AF_INET, NULL, 40001) != NULL);
	assert(lease_table_count() == 2);
	lease_table_clear();
}

int
main(void)
{
	test_ipv4();
	test_ipv6();
	test_expiry();
	printf("testmemmap: all tests passed\n");
	return 0;
}
