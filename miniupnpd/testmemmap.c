/* unit test of memmap.c : the rows it writes for the firewall rules and the
 * expiry of the pinholes. The firewall is a fake. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "config.h"
#include "macros.h"
#include "upnpredirect.h"
#include "upnputils.h"
#include "commonrdr.h"
#include "lease_table.h"
#include "memmap.h"
#if defined(USE_NETFILTER)
#include "netfilter/iptcrdr.h"
#ifdef USE_NFTABLES
#include "netfilter_nft/nftnlrdr.h"
#endif
#endif
#if defined(USE_PF)
#include "pf/obsdrdr.h"
#endif
/* the firewalls on which memmap.c reads pinholes, as in memmap.c */
#ifdef ENABLE_UPNPPINHOLE
#if defined(USE_NETFILTER) || (defined(USE_PF) && !defined(__APPLE__))
#define TEST_MAP6
#if defined(USE_NETFILTER)
#include "netfilter/iptpinhole.h"
#else
#include "pf/pfpinhole.h"
#endif
#endif
#endif

/* The fake firewall: memmap.c reads it, this test does not link a backend.
 * It holds no rule. A pass over the pinholes removes fake_removed rules. */
const char * ext_if_name = "wan";
static time_t fake_now;
static int fake_removed;
static int fake_partial;	/* the next pass leaves expired rules */

time_t
upnp_time(void)
{
	return fake_now;
}

const char *
proto_itoa(int proto)
{
	return proto == IPPROTO_TCP ? "TCP" : "UDP";
}

int
get_redirect_rule(const char * ifname, unsigned short eport, int proto,
                  char * iaddr, int iaddrlen, unsigned short * iport,
                  char * desc, int desclen, char * rhost, int rhostlen,
                  unsigned int * timestamp, u_int64_t * packets, u_int64_t * bytes)
{
	UNUSED(ifname); UNUSED(eport); UNUSED(proto); UNUSED(iaddr); UNUSED(iaddrlen);
	UNUSED(iport); UNUSED(desc); UNUSED(desclen); UNUSED(rhost); UNUSED(rhostlen);
	UNUSED(timestamp); UNUSED(packets); UNUSED(bytes);
	return -1;
}

int
get_redirect_rule_by_index(int index, char * ifname, unsigned short * eport,
                           char * iaddr, int iaddrlen, unsigned short * iport,
                           int * proto, char * desc, int desclen,
                           char * rhost, int rhostlen, unsigned int * timestamp,
                           u_int64_t * packets, u_int64_t * bytes)
{
	UNUSED(index); UNUSED(ifname); UNUSED(eport); UNUSED(iaddr); UNUSED(iaddrlen);
	UNUSED(iport); UNUSED(proto); UNUSED(desc); UNUSED(desclen); UNUSED(rhost);
	UNUSED(rhostlen); UNUSED(timestamp); UNUSED(packets); UNUSED(bytes);
	return -1;
}

#ifdef TEST_MAP6
int
find_pinhole(const char * ifname, const char * rem_host, unsigned short rem_port,
             const char * int_client, unsigned short int_port, int proto,
             char * desc, int desc_len, unsigned int * timestamp)
{
	UNUSED(ifname); UNUSED(rem_host); UNUSED(rem_port); UNUSED(int_client);
	UNUSED(int_port); UNUSED(proto); UNUSED(desc); UNUSED(desc_len); UNUSED(timestamp);
	return -2;
}

int
get_pinhole_info(unsigned short uid, char * rem_host, int rem_hostlen,
                 unsigned short * rem_port, char * int_client, int int_clientlen,
                 unsigned short * int_port, int * proto, char * desc, int desclen,
                 unsigned int * timestamp, u_int64_t * packets, u_int64_t * bytes)
{
	UNUSED(uid); UNUSED(rem_host); UNUSED(rem_hostlen); UNUSED(rem_port);
	UNUSED(int_client); UNUSED(int_clientlen); UNUSED(int_port); UNUSED(proto);
	UNUSED(desc); UNUSED(desclen); UNUSED(timestamp); UNUSED(packets); UNUSED(bytes);
	return -2;
}

int
get_pinhole_uid_by_index(int index)
{
	UNUSED(index);
	return -1;
}

int
clean_pinhole_list(unsigned int * next_timestamp)
{
	if(fake_partial) {
		memmap_remote_peers_partial();
		fake_partial = 0;
	}
	*next_timestamp = 1;	/* due : every pass reads the rules */
	return fake_removed;
}
#endif /* TEST_PINHOLES */

#ifdef PCP_PEER
int
get_peer_rule_by_index(int index, char * ifname, unsigned short * eport,
                       char * iaddr, int iaddrlen, unsigned short * iport,
                       int * proto, char * desc, int desclen,
                       char * rhost, int rhostlen, unsigned short * rport,
                       unsigned int * timestamp, u_int64_t * packets, u_int64_t * bytes)
{
	UNUSED(index); UNUSED(ifname); UNUSED(eport); UNUSED(iaddr); UNUSED(iaddrlen);
	UNUSED(iport); UNUSED(proto); UNUSED(desc); UNUSED(desclen); UNUSED(rhost);
	UNUSED(rhostlen); UNUSED(rport); UNUSED(timestamp); UNUSED(packets); UNUSED(bytes);
	return -1;
}

int
get_nat_ext_addr(struct sockaddr * src, struct sockaddr * dst, uint8_t proto,
                 struct sockaddr * ret_ext)
{
	UNUSED(src); UNUSED(dst); UNUSED(proto); UNUSED(ret_ext);
	return -1;
}
#endif /* PCP_PEER */

/* mapping_owner_of() of upnputils.c, which this test does not link: it would
 * bring the real upnp_time() and proto_itoa() */
static int
desc_has_pcp_nonce(const char * desc, const char * prefix)
{
	size_t n = strlen(prefix);
	return strncmp(desc, prefix, n) == 0 && strlen(desc) == n + 24 &&
	       strspn(desc + n, "0123456789abcdefABCDEF") == 24;
}

enum mapping_owner
mapping_owner_of(const char * desc, unsigned short eport, int proto)
{
	if(desc == NULL)
		return MAPPING_UPNP;
	if(desc_has_pcp_nonce(desc, "PCP MAP "))
		return MAPPING_PCP;
	if(strncmp(desc, "NAT-PMP ", 8) == 0) {
		char expected[64];
		snprintf(expected, sizeof(expected), "NAT-PMP %hu %s",
		         eport, proto_itoa(proto));
		if(strcmp(desc, expected) == 0)
			return MAPPING_NATPMP;
	}
	return MAPPING_UPNP;
}

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
	assert(memmap_map_kind(40001, IPPROTO_TCP) == LEASE_UPNP);
	assert(memmap_map_kind(40001, IPPROTO_UDP) == -1);

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
	assert(memmap_map_kind(40001, IPPROTO_TCP) == LEASE_NATPMP);
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
	/* a remote NULL, empty or "*" is no remote: the UPnP RemoteHost of any
	 * host */
	memmap_remote_peer(0, NULL, 0, 40001, "192.0.2.10", 8080, IPPROTO_TCP, "web", 610);
	memmap_remote_peer(0, "", 0, 40001, "192.0.2.10", 8080, IPPROTO_TCP, "web", 620);
	memmap_remote_peer(0, "*", 0, 40001, "192.0.2.10", 8080, IPPROTO_TCP, "web", 630);
	assert(lease_table_count() == 1);
	row = lease_table_find_external(IPPROTO_TCP, AF_INET, NULL, 40001, NULL, 0);
	assert(row != NULL && row->remote == NULL && row->expiry == 630);

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

#if defined(USE_NETFILTER) && !defined(USE_NFTABLES)
/* the port forwards of other programs, which port_in_use() reads with iptables:
 * there are none */
int
get_nat_redirect_rule(const char * nat_chain_name, const char * ifname, unsigned short eport,
                      int proto, char * iaddr, int iaddrlen, unsigned short * iport,
                      char * desc, int desclen, char * rhost, int rhostlen,
                      unsigned int * timestamp, u_int64_t * packets, u_int64_t * bytes)
{
	UNUSED(nat_chain_name); UNUSED(ifname); UNUSED(eport); UNUSED(proto);
	UNUSED(iaddr); UNUSED(iaddrlen); UNUSED(iport); UNUSED(desc); UNUSED(desclen);
	UNUSED(rhost); UNUSED(rhostlen); UNUSED(timestamp); UNUSED(packets); UNUSED(bytes);
	return -1;
}
#endif

#ifdef TEST_MAP6
/* One expiry pass over the pinholes at time now, in which the firewall removes
 * "removed" rules (< 0 : it fails). */
static void
expire_map6(time_t now, int removed)
{
	unsigned int next;

	fake_now = now;
	fake_removed = removed;
	(void)memmap_expire_map6(&next);
}

static void
test_map6_expiry(void)
{
	char iaddr[64];
	unsigned int i;

	lease_table_clear();
	memmap_map(1, 6001, "2001:db8::1", 6001, IPPROTO_TCP, "a", 90);	/* expired */
	memmap_map(2, 6002, "2001:db8::1", 6002, IPPROTO_TCP, "b", 150);
	memmap_map(3, 6003, "2001:db8::1", 6003, IPPROTO_TCP, "c", 0);	/* no expiry */
	assert(lease_table_count() == 3);

	/* the firewall failed : the rows stay */
	expire_map6(100, -1);
	assert(lease_table_count() == 3);

	/* a pass which leaves expired rules keeps the rows, once. It comes a
	 * second after the failed one, not on the next turn of the main loop */
	fake_partial = 1;
	expire_map6(100, 1);
	assert(fake_partial == 1);	/* no read */
	expire_map6(101, 1);
	assert(fake_partial == 0);
	assert(lease_table_count() == 3);

	/* a full pass removes the expired row only */
	expire_map6(102, 1);
	assert(lease_table_count() == 2);
	assert(lease_table_find_uid(1) == NULL);
	assert(lease_table_find_uid(2) != NULL && lease_table_find_uid(3) != NULL);

	/* a renewal by uid moves the expiry */
	memmap_renew_uid(2, 300);
	expire_map6(200, 1);
	assert(lease_table_count() == 2);
	expire_map6(300, 1);
	assert(lease_table_count() == 1);

	/* a full pass which removed no rule : the rule of the expired row was
	 * already gone, and the row goes too */
	memmap_map(4, 6004, "2001:db8::1", 6004, IPPROTO_TCP, "d", 350);
	expire_map6(400, 0);
	assert(lease_table_count() == 1);
	assert(lease_table_find_uid(4) == NULL);
	lease_table_clear();

	/* many expired pinholes, removed during one walk; an IPv4 mapping is not a
	 * pinhole, whatever its expiry */
	for(i = 0; i < 600; i++) {
		snprintf(iaddr, sizeof(iaddr), "2001:db8::%x", i + 1);
		memmap_map((unsigned short)(i + 1), 0, iaddr, 8080, IPPROTO_UDP, "upnp", 100);
	}
	memmap_map(1000, 0, "2001:db8:1::1", 8080, IPPROTO_UDP, "upnp", 101);
	memmap_map(1001, 0, "2001:db8:1::2", 8080, IPPROTO_UDP, "upnp", 0);
	memmap_map(0, 40001, "192.0.2.10", 8080, IPPROTO_TCP, "web", 50);
	assert(lease_table_count() == 603);

	expire_map6(99, 600);
	assert(lease_table_count() == 603);
	expire_map6(100, 600);
	assert(lease_table_count() == 3);
	assert(lease_table_find_uid(1) == NULL && lease_table_find_uid(600) == NULL);
	assert(lease_table_find_uid(1000) != NULL);
	expire_map6(101, 1);
	assert(lease_table_find_uid(1000) == NULL);
	/* 0 : no expiry */
	expire_map6(0x7fffffff, 1);
	assert(lease_table_find_uid(1001) != NULL);
	assert(lease_table_find_mapping(IPPROTO_TCP, AF_INET, NULL, 40001) != NULL);
	assert(lease_table_count() == 2);
	lease_table_clear();
}

/* A remote port with any remote host, and a row found by its key with
 * another uid */
static void
test_map6_keys(void)
{
	static const char * h = "2001:db8::10";
	struct lease_entry * a, * b;

	lease_table_clear();
	/* two pinholes which differ only by the remote port : two rows */
	memmap_remote_peer(1, "", 1000, 0, h, 8080, IPPROTO_UDP, "IGD2 pinhole", 100);
	memmap_remote_peer(2, "*", 2000, 0, h, 8080, IPPROTO_UDP, "IGD2 pinhole", 100);
	a = lease_table_find_uid(1);
	b = lease_table_find_uid(2);
	assert(a != NULL && b != NULL && a != b && lease_table_count() == 2);
	assert(a->remote != NULL && a->remote->rport == 1000);
	assert(IN6_IS_ADDR_UNSPECIFIED(&a->remote->raddr));
	assert(map6(h, 8080, NULL, 0) == NULL);
	/* :: with port 0 is no remote at all */
	memmap_remote_peer(3, "::", 0, 0, h, 8080, IPPROTO_UDP, "IGD2 pinhole", 100);
	assert(map6(h, 8080, NULL, 0) == lease_table_find_uid(3));
	assert(lease_table_count() == 3);

	/* the delete fallback by the rule, with the port */
	memmap_remote_peer_gone_at(99, "::", 1000, h, 8080, IPPROTO_UDP);
	assert(lease_table_find_uid(1) == NULL && lease_table_find_uid(2) == b);
	assert(lease_table_count() == 2);

	/* a row on the key with another uid : the new uid replaces it */
	lease_table_clear();
	memmap_map(5, 0, h, 7070, IPPROTO_UDP, "upnp", 100);
	memmap_map(6, 0, h, 7070, IPPROTO_UDP, "upnp", 200);
	a = lease_table_find_uid(6);
	assert(a != NULL && lease_uid(a) == 6 && a->expiry == 200);
	assert(lease_table_find_uid(5) == NULL && lease_table_count() == 1);
	lease_table_clear();
}
#endif /* TEST_PINHOLES */

int
main(void)
{
	test_ipv4();
	test_ipv6();
#ifdef TEST_MAP6
	test_map6_expiry();
	test_map6_keys();
#endif
	printf("testmemmap: all tests passed\n");
	return 0;
}
