/* unit test of memmap.c : the rows it writes for the firewall rules */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "config.h"
#include "upnputils.h"
#include "upnpglobalvars.h"
#include "lease_table.h"
#include "memmap.h"

/* upnputils.o, for the real mapping_owner_of(), needs these */
struct lan_addr_list lan_addrs;
int runtime_flags = 0;
time_t startup_time = 0;

#define PCP_DESC	"PCP MAP 0102030405060708090a0b0c"

/* the nonce of a PCP request as it comes off the wire */
static const unsigned char wire_nonce[12] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c
};

/* the description pcpserver.c writes for a MAP with that nonce */
static const char *
pcp_desc(void)
{
	static char desc[64];
	uint32_t nonce[3];
	memcpy(nonce, wire_nonce, sizeof(nonce));
	snprintf(desc, sizeof(desc), "PCP MAP %08x%08x%08x",
	         nonce[0], nonce[1], nonce[2]);
	return desc;
}

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
map6(const char * iaddr, unsigned short iport, const char * raddr,
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
	memmap_map(0, 40001, "192.0.2.11", 9090, IPPROTO_TCP, "NAT-PMP 40001 TCP", 300);
	again = lease_table_find_mapping(IPPROTO_TCP, AF_INET, NULL, 40001);
	assert(again != NULL && lease_table_count() == 1);
	assert(again->kind == LEASE_NATPMP);
	assert(same_addr(&again->iaddr, "::ffff:192.0.2.11") && again->iport == 9090);
	assert(again->expiry == 300 && strcmp(again->label, "NAT-PMP 40001 TCP") == 0);

	/* NAT-PMP writes the port and protocol of the rule itself, in upper
	 * case. Any other text is UPnP */
	memmap_map(0, 40001, "192.0.2.11", 9090, IPPROTO_TCP, "NAT-PMP 40001 tcp", 300);
	row = lease_table_find_mapping(IPPROTO_TCP, AF_INET, NULL, 40001);
	assert(row->kind == LEASE_UPNP);
	memmap_map(0, 40001, "192.0.2.11", 9090, IPPROTO_TCP, "NAT-PMP 40002 TCP", 300);
	row = lease_table_find_mapping(IPPROTO_TCP, AF_INET, NULL, 40001);
	assert(row->kind == LEASE_UPNP);

	/* a PCP owner : the nonce from the description, in the bytes of the
	 * wire, whatever the byte order of the host */
	memmap_map(0, 40001, "192.0.2.11", 9090, IPPROTO_TCP, pcp_desc(), 300);
	row = lease_table_find_mapping(IPPROTO_TCP, AF_INET, NULL, 40001);
	assert(row->kind == LEASE_PCP_MAP && lease_uid(row) == 0);
	assert(memcmp(row->nonce, wire_nonce, sizeof(wire_nonce)) == 0);
	/* a nonce of other than 24 digits is not PCP */
	memmap_map(0, 40001, "192.0.2.11", 9090, IPPROTO_TCP, PCP_DESC "0", 300);
	row = lease_table_find_mapping(IPPROTO_TCP, AF_INET, NULL, 40001);
	assert(row->kind == LEASE_UPNP);

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
	assert(row != NULL && row == map6(h, 8080, NULL, 0));
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
	assert(row != NULL && row == map6(h, 8080, peer, 5000));
	assert(row->remote != NULL && row->remote->rport == 5000);
	memmap_remote_peer_gone(9);
	assert(lease_table_find_uid(9) == NULL && lease_table_count() == 1);
	memmap_remote_peer_gone(9);	/* no row : nothing */
	assert(lease_table_count() == 1);

	/* PCP has no uid : the row is found by its key */
	memmap_remote_peer(0, peer, 5000, 0, h, 9090, IPPROTO_UDP, PCP_DESC, 700);
	row = map6(h, 9090, peer, 5000);
	assert(row != NULL && row->kind == LEASE_PCP_MAP && lease_uid(row) == 0);
	assert(lease_table_count() == 2);
	/* a renewal by the key keeps the row */
	memmap_remote_peer(0, peer, 5000, 0, h, 9090, IPPROTO_UDP, PCP_DESC, 800);
	assert(map6(h, 9090, peer, 5000) == row && row->expiry == 800);
	/* the firewall gives the remote of a rule : the row goes */
	memmap_remote_peer_gone_at(0, peer, 5000, h, 9090, IPPROTO_UDP);
	assert(map6(h, 9090, peer, 5000) == NULL && lease_table_count() == 1);

	/* a PCP MAP pinhole has no remote, and the firewall gives :: for it */
	memmap_map(0, 0, h, 9091, IPPROTO_UDP, PCP_DESC, 900);
	assert(map6(h, 9091, NULL, 0) != NULL && lease_table_count() == 2);
	memmap_remote_peer_gone_at(0, "::", 0, h, 9091, IPPROTO_UDP);
	assert(map6(h, 9091, NULL, 0) == NULL && lease_table_count() == 1);

	/* gone_at with a uid takes the row of the uid */
	memmap_remote_peer_gone_at(7, NULL, 0, h, 1, IPPROTO_UDP);
	assert(lease_table_find_uid(7) == NULL && lease_table_count() == 0);

	/* a bad internal address : no row */
	memmap_map(3, 0, "2001:db8::zz", 8080, IPPROTO_UDP, "upnp", 100);
	assert(lease_table_count() == 0);
}

/* the rules which are still in the firewall, for the lookup of the expiry */
static struct {
	const char * iaddr;
	unsigned short iport;
	const char * raddr;
	unsigned short rport;
	unsigned int timestamp;
} fw_rules[4];
static unsigned int fw_n, fw_lookups;

static int
fw_lookup(const char * raddr, unsigned short rport, const char * iaddr,
          unsigned short iport, int proto, unsigned int * timestamp)
{
	unsigned int i;
	(void)proto;
	fw_lookups++;
	for(i = 0; i < fw_n; i++) {
		if(strcmp(fw_rules[i].iaddr, iaddr) != 0 || fw_rules[i].iport != iport)
			continue;
		if((fw_rules[i].raddr == NULL) != (raddr == NULL))
			continue;
		if(raddr != NULL && (strcmp(fw_rules[i].raddr, raddr) != 0 ||
		                     fw_rules[i].rport != rport))
			continue;
		*timestamp = fw_rules[i].timestamp;
		return 0;
	}
	return -1;
}

static void
test_expiry(void)
{
	char iaddr[64];
	unsigned int i;

	lease_table_clear();
	fw_n = 0;
	/* more expired pinholes than the old walk of 256 took */
	for(i = 0; i < 600; i++) {
		snprintf(iaddr, sizeof(iaddr), "2001:db8::%x", i + 1);
		memmap_map((unsigned short)(i + 1), 0, iaddr, 8080, IPPROTO_UDP, "upnp", 100);
	}
	memmap_map(1000, 0, "2001:db8:1::1", 8080, IPPROTO_UDP, "upnp", 101);
	memmap_map(1001, 0, "2001:db8:1::2", 8080, IPPROTO_UDP, "upnp", 0);
	/* an IPv4 mapping is not a pinhole, whatever its expiry */
	memmap_map(0, 40001, "192.0.2.10", 8080, IPPROTO_TCP, "web", 50);
	assert(lease_table_count() == 603);

	fw_lookups = 0;
	memmap_remote_peers_expired(99, fw_lookup);
	assert(lease_table_count() == 603 && fw_lookups == 0);
	memmap_remote_peers_expired(100, fw_lookup);
	assert(lease_table_count() == 3 && fw_lookups == 600);
	assert(lease_table_find_uid(1) == NULL && lease_table_find_uid(600) == NULL);
	assert(lease_table_find_uid(1000) != NULL);
	memmap_remote_peers_expired(101, fw_lookup);
	assert(lease_table_find_uid(1000) == NULL);
	/* 0 : no expiry */
	memmap_remote_peers_expired(0xffffffffu, fw_lookup);
	assert(lease_table_find_uid(1001) != NULL);
	assert(lease_table_find_mapping(IPPROTO_TCP, AF_INET, NULL, 40001) != NULL);
	assert(lease_table_count() == 2);
	lease_table_clear();
}

/* A row goes only if the firewall removed its rule. */
static void
test_expiry_rule_kept(void)
{
	static const char * h = "2001:db8::10", * peer = "2001:db8:1::5";
	struct lease_entry * row;

	lease_table_clear();
	memmap_map(1, 0, h, 8080, IPPROTO_UDP, "upnp", 100);
	memmap_map(2, 0, h, 8081, IPPROTO_UDP, "upnp", 100);
	memmap_remote_peer(0, peer, 5000, 0, h, 9090, IPPROTO_UDP, PCP_DESC, 100);
	memmap_remote_peer(0, peer, 5001, 0, h, 9090, IPPROTO_UDP, PCP_DESC, 100);
	assert(lease_table_count() == 4);

	/* the removal of uid 1 failed : the rule is still there, expired */
	fw_rules[0].iaddr = h; fw_rules[0].iport = 8080;
	fw_rules[0].raddr = NULL; fw_rules[0].timestamp = 100;
	/* the PEER rule was renewed one second later than its row */
	fw_rules[1].iaddr = h; fw_rules[1].iport = 9090;
	fw_rules[1].raddr = peer; fw_rules[1].rport = 5000;
	fw_rules[1].timestamp = 101;
	fw_n = 2;
	memmap_remote_peers_expired(100, fw_lookup);
	assert(lease_table_count() == 2);
	row = lease_table_find_uid(1);
	assert(row != NULL && row->expiry == 100);
	assert(lease_table_find_uid(2) == NULL);
	row = map6(h, 9090, peer, 5000);
	assert(row != NULL && row->expiry == 101);
	assert(map6(h, 9090, peer, 5001) == NULL);

	/* the next pass, after the firewall removed both */
	fw_n = 0;
	memmap_remote_peers_expired(101, fw_lookup);
	assert(lease_table_count() == 0);
}

int
main(void)
{
	test_ipv4();
	test_ipv6();
	test_expiry();
	test_expiry_rule_kept();
	printf("testmemmap: all tests passed\n");
	return 0;
}
