/* unit test of memmap.c : the rows memmap_sync() writes for the firewall
 * rules, the lookups by internal endpoint and the expiry. The firewall is a
 * fake which takes every change. testmemmapsync.c tests memmap_sync() itself:
 * what it does when the firewall refuses a request. */
#include <assert.h>
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
#include "upnpglobalvars.h"
#include "fwsync.h"
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
#define TEST_PINHOLES
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
int firewall_trust = FW_TRUST_CHECK;
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

/* the redirect rules of the fake firewall, with their counters, and the
 * number of times it was read */
struct fake_rule {
	unsigned short eport;
	int proto;
	u_int64_t packets;
	u_int64_t bytes;
};
static struct fake_rule fake_rules[4];
static int fake_rule_count;
static int fake_reads;

int
get_redirect_rule(const char * ifname, unsigned short eport, int proto,
                  char * iaddr, int iaddrlen, unsigned short * iport,
                  char * desc, int desclen, char * rhost, int rhostlen,
                  unsigned int * timestamp, u_int64_t * packets, u_int64_t * bytes)
{
	int i;
	UNUSED(ifname); UNUSED(iaddr); UNUSED(iaddrlen);
	UNUSED(iport); UNUSED(desc); UNUSED(desclen); UNUSED(rhost); UNUSED(rhostlen);
	UNUSED(timestamp);
	fake_reads++;
	for(i = 0; i < fake_rule_count; i++) {
		if(fake_rules[i].eport == eport && fake_rules[i].proto == proto) {
			*packets = fake_rules[i].packets;
			*bytes = fake_rules[i].bytes;
			return 0;
		}
	}
	return -2;	/* not found */
}

int
get_redirect_rule_by_index(int index, char * ifname, unsigned short * eport,
                           char * iaddr, int iaddrlen, unsigned short * iport,
                           int * proto, char * desc, int desclen,
                           char * rhost, int rhostlen, unsigned int * timestamp,
                           u_int64_t * packets, u_int64_t * bytes)
{
	UNUSED(ifname); UNUSED(iaddr); UNUSED(iaddrlen);
	UNUSED(iport); UNUSED(desc); UNUSED(desclen); UNUSED(rhost);
	UNUSED(rhostlen); UNUSED(timestamp);
	fake_reads++;
	if(index < 0 || index >= fake_rule_count)
		return -1;
	*eport = fake_rules[index].eport;
	*proto = fake_rules[index].proto;
	*packets = fake_rules[index].packets;
	*bytes = fake_rules[index].bytes;
	return 0;
}

#if defined(USE_NETFILTER) && !defined(USE_NFTABLES)
int
get_redirect_rules_counters(void (*fn)(unsigned short eport, int proto,
                                       u_int64_t packets, u_int64_t bytes, void * arg),
                            void * arg)
{
	int i;
	fake_reads++;
	for(i = 0; i < fake_rule_count; i++)
		fn(fake_rules[i].eport, fake_rules[i].proto, fake_rules[i].packets,
		   fake_rules[i].bytes, arg);
	return 0;
}
#endif

#ifdef TEST_PINHOLES
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

/* fw_map_rule() of fwsync.c, which this test does not link: the same read */
int
fw_map_rule(unsigned short eport, int proto, u_int64_t * packets, u_int64_t * bytes)
{
	unsigned short iport;
	unsigned int timestamp;
	int r = get_redirect_rule(NULL, eport, proto, NULL, 0, &iport, NULL, 0,
	                          NULL, 0, &timestamp, packets, bytes);
	return r >= 0 ? 0 : r == -2 ? -2 : -1;
}

/* The fake fw_sync(): it takes every change, and gives a new pinhole the uid
 * of fake_uid. */
static int fake_uid;
unsigned int nextruletoclean_timestamp;

int
fw_sync(struct fw_change * changes, int n)
{
	int i;
	for(i = 0; i < n; i++) {
		if(changes[i].op == FW_ADD && changes[i].row->family == AF_INET6)
			changes[i].uid = (unsigned short)fake_uid;
		changes[i].applied = FW_APPLIED;
	}
	return 0;
}

/* A request of one change, as the protocols send it. uid is the one the
 * firewall gives a new pinhole, or the pinhole to renew or delete. */
static int
sync1(enum memmap_op op, int uid, const char * raddr, unsigned short rport,
      unsigned short eport, const char * iaddr, unsigned short iport, int proto,
      const char * desc, unsigned int timestamp)
{
	struct memmap_change c;
	memset(&c, 0, sizeof(c));
	c.op = op;
	c.raddr = raddr;
	c.rport = rport;
	c.eport = eport;
	c.iaddr = iaddr;
	c.iport = iport;
	c.proto = proto;
	c.desc = desc;
	c.timestamp = timestamp;
	c.uid = uid;
	fake_uid = uid;
	return memmap_sync(&c, 1);
}

/* add a mapping with no remote peer */
static void
add_map(int uid, unsigned short eport, const char * iaddr, unsigned short iport,
        int proto, const char * desc, unsigned int timestamp)
{
	(void)sync1(MEMMAP_ADD, uid, NULL, 0, eport, iaddr, iport, proto, desc, timestamp);
}

/* add a mapping limited to a remote peer */
static void
add_peer(int uid, const char * raddr, unsigned short rport, unsigned short eport,
         const char * iaddr, unsigned short iport, int proto, const char * desc,
         unsigned int timestamp)
{
	(void)sync1(MEMMAP_ADD, uid, raddr, rport, eport, iaddr, iport, proto, desc, timestamp);
}

/* renew a pinhole by its rule, and by uid if it has one */
static void
renew(int uid, const char * raddr, unsigned short rport, const char * iaddr,
      unsigned short iport, int proto, const char * desc, unsigned int timestamp)
{
	(void)sync1(MEMMAP_RENEW, uid, raddr, rport, 0, iaddr, iport, proto, desc, timestamp);
}

/* renew a pinhole by uid alone: a new expiry */
static void
renew_uid(int uid, unsigned int timestamp)
{
	(void)sync1(MEMMAP_RENEW, uid, NULL, 0, 0, NULL, 0, 0, NULL, timestamp);
}

static void
drop_map(unsigned short eport, int proto)
{
	(void)sync1(MEMMAP_DELETE, 0, NULL, 0, eport, NULL, 0, proto, NULL, 0);
}

/* delete a pinhole by uid, or else by its rule */
static void
drop_pinhole(int uid, const char * raddr, unsigned short rport,
             const char * iaddr, unsigned short iport, int proto)
{
	(void)sync1(MEMMAP_DELETE_PINHOLE, uid, raddr, rport, 0, iaddr, iport, proto, NULL, 0);
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
	add_map(0, 40001, "192.0.2.10", 8080, IPPROTO_TCP, "web", 100);
	row = lease_table_find_mapping(IPPROTO_TCP, AF_INET, NULL, 40001);
	assert(row != NULL && lease_table_count() == 1);
	assert(row->kind == LEASE_UPNP && lease_uid(row) == 0);
	assert(same_addr(&row->iaddr, "::ffff:192.0.2.10") && row->iport == 8080);
	assert(row->expiry == 100 && strcmp(row->label, "web") == 0);
	assert(row->remote == NULL);

	/* the same key again : one row, with the new expiry and label */
	add_map(0, 40001, "192.0.2.10", 8080, IPPROTO_TCP, "web2", 200);
	row = lease_table_find_mapping(IPPROTO_TCP, AF_INET, NULL, 40001);
	assert(row != NULL && lease_table_count() == 1);
	assert(row->expiry == 200 && strcmp(row->label, "web2") == 0);

	/* the same key for another client and owner : the row is replaced */
	add_map(0, 40001, "192.0.2.11", 9090, IPPROTO_TCP, "NAT-PMP 40001 tcp", 300);
	again = lease_table_find_mapping(IPPROTO_TCP, AF_INET, NULL, 40001);
	assert(again != NULL && lease_table_count() == 1);
	assert(again->kind == LEASE_NATPMP);
	assert(same_addr(&again->iaddr, "::ffff:192.0.2.11") && again->iport == 9090);
	assert(again->expiry == 300 && strcmp(again->label, "NAT-PMP 40001 tcp") == 0);

	/* a PCP owner : the nonce from the description */
	add_map(0, 40001, "192.0.2.11", 9090, IPPROTO_TCP, PCP_DESC, 300);
	row = lease_table_find_mapping(IPPROTO_TCP, AF_INET, NULL, 40001);
	assert(row->kind == LEASE_PCP_MAP && lease_uid(row) == 0);
	assert(row->nonce[0] == 0x01 && row->nonce[11] == 0x0c);

	/* no label */
	add_map(0, 40001, "192.0.2.11", 9090, IPPROTO_TCP, NULL, 300);
	row = lease_table_find_mapping(IPPROTO_TCP, AF_INET, NULL, 40001);
	assert(row != NULL && row->label == NULL && row->kind == LEASE_UPNP);

	/* a remote : the row with no remote is replaced by one with it */
	add_peer(0, "203.0.113.5", 5000, 40001, "192.0.2.10", 8080,
	         IPPROTO_TCP, "peer", 400);
	assert(lease_table_count() == 1);
	row = lease_table_find_external(IPPROTO_TCP, AF_INET, NULL, 40001, &r, 5000);
	assert(row != NULL && row->remote != NULL && row->expiry == 400);
	assert(lease_table_find_external(IPPROTO_TCP, AF_INET, NULL, 40001, NULL, 0) == NULL);
	/* and again with the same remote */
	add_peer(0, "203.0.113.5", 5000, 40001, "192.0.2.10", 8080,
	         IPPROTO_TCP, "peer", 500);
	again = lease_table_find_external(IPPROTO_TCP, AF_INET, NULL, 40001, &r, 5000);
	assert(again != NULL && again->expiry == 500 && lease_table_count() == 1);
	/* another remote port is not a renewal : the row takes it */
	add_peer(0, "203.0.113.5", 5001, 40001, "192.0.2.10", 8080,
	         IPPROTO_TCP, "peer", 550);
	assert(lease_table_find_external(IPPROTO_TCP, AF_INET, NULL, 40001, &r, 5000) == NULL);
	again = lease_table_find_external(IPPROTO_TCP, AF_INET, NULL, 40001, &r, 5001);
	assert(again != NULL && again->expiry == 550 && lease_table_count() == 1);
	/* and back to no remote */
	add_map(0, 40001, "192.0.2.10", 8080, IPPROTO_TCP, "web", 600);
	assert(lease_table_count() == 1);
	row = lease_table_find_external(IPPROTO_TCP, AF_INET, NULL, 40001, NULL, 0);
	assert(row != NULL && row->expiry == 600);

	/* other protocol, other row */
	add_map(0, 40001, "192.0.2.10", 8080, IPPROTO_UDP, "web", 600);
	assert(lease_table_count() == 2);
	drop_map(40001, IPPROTO_TCP);
	assert(lease_table_find_mapping(IPPROTO_TCP, AF_INET, NULL, 40001) == NULL);
	assert(lease_table_find_mapping(IPPROTO_UDP, AF_INET, NULL, 40001) != NULL);
	drop_map(40001, IPPROTO_TCP);	/* no row : nothing */
	assert(lease_table_count() == 1);

	/* an address which is not IPv4 or IPv6 : no row */
	add_map(0, 40002, "not an address", 8080, IPPROTO_TCP, "web", 600);
	assert(lease_table_count() == 1);

	/* a remote host which does not parse : no row, not a mapping for any
	 * remote */
	add_peer(0, "example.com", 0, 40003, "192.0.2.10", 8080, IPPROTO_TCP, "web", 600);
	add_peer(0, " 192.0.2.99", 0, 40004, "192.0.2.10", 8080, IPPROTO_TCP, "web", 600);
	assert(lease_table_count() == 1);
}

static void
test_ipv6(void)
{
	static const char * h = "2001:db8::10", * peer = "2001:db8:1::5";
	struct lease_entry * row, * again;

	lease_table_clear();
	/* a UPnP pinhole : found by its uid */
	add_map(7, 0, h, 8080, IPPROTO_UDP, "upnp", 100);
	row = lease_table_find_uid(7);
	assert(row != NULL && row == pinhole(h, 8080, NULL, 0));
	assert(row->family == AF_INET6 && row->eport == 8080 && row->iport == 8080);
	assert(same_addr(&row->eaddr, h) && same_addr(&row->iaddr, h));
	assert(row->kind == LEASE_UPNP && lease_uid(row) == 7);

	/* renew by uid, without a description */
	renew_uid(7, 200);
	assert(lease_table_find_uid(7) == row && row->expiry == 200);
	renew_uid(7, 300);
	assert(row->expiry == 300 && strcmp(row->label, "upnp") == 0);
	renew_uid(8, 999);	/* no row : nothing */
	assert(lease_table_count() == 1);

	/* renew with the same description : the row stays */
	renew(7, NULL, 0, h, 8080, IPPROTO_UDP, "upnp", 400);
	assert(lease_table_find_uid(7) == row && row->expiry == 400);

	/* another description on the key : the row takes it */
	renew(7, NULL, 0, h, 8080, IPPROTO_UDP, "other", 500);
	again = lease_table_find_uid(7);
	assert(again != NULL && strcmp(again->label, "other") == 0);
	assert(again->expiry == 500 && lease_table_count() == 1);

	/* a pinhole with a remote : its own row next to the one without */
	add_peer(9, peer, 5000, 0, h, 8080, IPPROTO_UDP, "upnp peer", 600);
	assert(lease_table_count() == 2);
	row = lease_table_find_uid(9);
	assert(row != NULL && row == pinhole(h, 8080, peer, 5000));
	assert(row->remote != NULL && row->remote->rport == 5000);
	drop_pinhole(9, NULL, 0, NULL, 0, 0);
	assert(lease_table_find_uid(9) == NULL && lease_table_count() == 1);
	drop_pinhole(9, NULL, 0, NULL, 0, 0);	/* no row : nothing */
	assert(lease_table_count() == 1);

	/* PCP has no uid : the row is found by its key */
	add_peer(0, peer, 5000, 0, h, 9090, IPPROTO_UDP, PCP_DESC, 700);
	row = pinhole(h, 9090, peer, 5000);
	assert(row != NULL && row->kind == LEASE_PCP_MAP && lease_uid(row) == 0);
	assert(lease_table_count() == 2);
	/* a renewal by the key keeps the row */
	renew(0, peer, 5000, h, 9090, IPPROTO_UDP, PCP_DESC, 800);
	assert(pinhole(h, 9090, peer, 5000) == row && row->expiry == 800);
	/* the firewall gives the remote of a rule : the row goes */
	drop_pinhole(0, peer, 5000, h, 9090, IPPROTO_UDP);
	assert(pinhole(h, 9090, peer, 5000) == NULL && lease_table_count() == 1);

	/* a PCP MAP pinhole has no remote, and the firewall gives :: for it */
	add_map(0, 0, h, 9091, IPPROTO_UDP, PCP_DESC, 900);
	assert(pinhole(h, 9091, NULL, 0) != NULL && lease_table_count() == 2);
	drop_pinhole(0, "::", 0, h, 9091, IPPROTO_UDP);
	assert(pinhole(h, 9091, NULL, 0) == NULL && lease_table_count() == 1);

	/* a delete with a uid takes the row of the uid */
	drop_pinhole(7, NULL, 0, h, 1, IPPROTO_UDP);
	assert(lease_table_find_uid(7) == NULL && lease_table_count() == 0);

	/* a bad internal address : no row */
	add_map(3, 0, "2001:db8::zz", 8080, IPPROTO_UDP, "upnp", 100);
	assert(lease_table_count() == 0);

	/* A PCP pinhole renewed with the uid the firewall gave it, which a
	 * UPnP row of another key holds: the renewal takes the row of its key,
	 * and the other row stays */
	add_map(11, 0, h, 6060, IPPROTO_UDP, "upnp", 100);
	add_map(11, 0, h, 6061, IPPROTO_UDP, PCP_DESC, 100);
	assert(lease_table_count() == 2);
	renew(11, NULL, 0, h, 6061, IPPROTO_UDP, PCP_DESC, 200);
	assert(lease_table_count() == 2);
	row = pinhole(h, 6061, NULL, 0);
	assert(row != NULL && row->kind == LEASE_PCP_MAP && row->expiry == 200);
	row = lease_table_find_uid(11);
	assert(row != NULL && row->iport == 6060 && row->expiry == 100);
	lease_table_clear();

	/* a remote host which does not parse : no row, not a pinhole for any
	 * remote */
	add_peer(4, "example.com", 0, 0, h, 7070, IPPROTO_UDP, "upnp", 100);
	assert(lease_table_count() == 0);

	/* a remote port with any remote host : the row keeps the port */
	add_peer(5, "", 5000, 0, h, 7071, IPPROTO_UDP, "upnp", 100);
	row = lease_table_find_uid(5);
	assert(row != NULL && row->remote != NULL && row->remote->rport == 5000);
	assert(IN6_IS_ADDR_UNSPECIFIED(&row->remote->raddr));
	/* the key with no remote port is another pinhole */
	assert(pinhole(h, 7071, NULL, 0) == NULL);
	lease_table_clear();
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

/* 1000 clients ask for the external port another one holds: each is told the
 * port is in use, by both checks, the holder is not, and the table keeps the
 * one row */
static void
test_one_port_many_clients(void)
{
	static const char * holder = "10.0.0.1";
	char h[INET_ADDRSTRLEN];
	int i, in_use = 0, used_by_other = 0;

	lease_table_clear();
	add_map(0, 40001, holder, 5000, IPPROTO_UDP, "holder", 1000);
	for(i = 1; i <= 1000; i++) {
		snprintf(h, sizeof(h), "10.0.%d.%d", i / 250, i % 250 + 1);
		in_use += memmap_eport_redirected_elsewhere("wan", 40001, IPPROTO_UDP, h, 5000);
		used_by_other += memmap_eport_used_by_other(40001, h);
	}
	assert(in_use == 1000 && used_by_other == 1000);
	assert(lease_table_count() == 1);

	/* the holder may have it, but not for another internal port */
	assert(memmap_eport_redirected_elsewhere("wan", 40001, IPPROTO_UDP, holder, 5000) == 0);
	assert(memmap_eport_redirected_elsewhere("wan", 40001, IPPROTO_UDP, holder, 5001) == 1);
	assert(memmap_eport_used_by_other(40001, holder) == 0);
	/* the other protocol has no mapping of the port */
	assert(memmap_eport_redirected_elsewhere("wan", 40001, IPPROTO_TCP, h, 5000) == 0);
	/* once the holder is gone, the port is free for any of them */
	drop_map(40001, IPPROTO_UDP);
	assert(memmap_eport_redirected_elsewhere("wan", 40001, IPPROTO_UDP, h, 5000) == 0);
	assert(memmap_eport_used_by_other(40001, h) == 0);
	lease_table_clear();
}

static void
test_find_map(void)
{
	static const char * h1 = "192.0.2.10";
	unsigned short eport = 0;
	char desc[64];
	unsigned int ts = 0;

	lease_table_clear();
	/* a UPnP row, then the NAT-PMP and PCP rows of the same internal endpoint */
	add_map(0, 40001, h1, 5000, IPPROTO_UDP, "upnp app", 1000);
	add_map(0, 40002, h1, 5000, IPPROTO_UDP, "NAT-PMP 40002 UDP", 2000);
	add_map(0, 40003, h1, 5000, IPPROTO_UDP, PCP_DESC, 3000);

	assert(memmap_find_map(h1, 5000, IPPROTO_UDP, MAPPING_NATPMP,
	                       &eport, desc, sizeof(desc), &ts) == 0);
	assert(eport == 40002 && ts == 2000);
	assert(strcmp(desc, "NAT-PMP 40002 UDP") == 0);
	assert(memmap_find_map(h1, 5000, IPPROTO_UDP, MAPPING_UPNP,
	                       &eport, NULL, 0, NULL) == 0 && eport == 40001);
	assert(memmap_find_map(h1, 5000, IPPROTO_UDP, MAPPING_PCP,
	                       &eport, NULL, 0, NULL) == 0 && eport == 40003);
	/* any owner : one of the three rows */
	assert(memmap_find_map(h1, 5000, IPPROTO_UDP, -1, &eport, NULL, 0, NULL) == 0);
	assert(eport >= 40001 && eport <= 40003);

	/* only the UPnP row left : no NAT-PMP row, whatever comes first */
	drop_map(40002, IPPROTO_UDP);
	drop_map(40003, IPPROTO_UDP);
	assert(memmap_find_map(h1, 5000, IPPROTO_UDP, MAPPING_NATPMP,
	                       &eport, NULL, 0, NULL) == -1);

	/* another port, protocol or address is another endpoint */
	assert(memmap_find_map(h1, 5001, IPPROTO_UDP, -1, &eport, NULL, 0, NULL) == -1);
	assert(memmap_find_map(h1, 5000, IPPROTO_TCP, -1, &eport, NULL, 0, NULL) == -1);
	assert(memmap_find_map("192.0.2.11", 5000, IPPROTO_UDP, -1,
	                       &eport, NULL, 0, NULL) == -1);
	assert(memmap_find_map("not an address", 5000, IPPROTO_UDP, -1,
	                       &eport, NULL, 0, NULL) == -1);
	lease_table_clear();
}

static void
test_expired_maps(void)
{
	struct expired_redirect expired[EXPIRE_MAX_PER_PASS];
	unsigned int next = 1;
	int i, n;

	lease_table_clear();
	/* nothing : no expiry to come back for */
	assert(memmap_expired_maps(100, expired, EXPIRE_MAX_PER_PASS, &next) == 0);
	assert(next == 0);

	add_map(0, 40001, "192.0.2.10", 5000, IPPROTO_TCP, "a", 90);	/* expired */
	add_map(0, 40002, "192.0.2.10", 5001, IPPROTO_UDP, "b", 100);	/* expires now */
	add_map(0, 40003, "192.0.2.10", 5002, IPPROTO_TCP, "c", 150);
	add_map(0, 40004, "192.0.2.10", 5003, IPPROTO_TCP, "d", 120);
	add_map(0, 40005, "192.0.2.10", 5004, IPPROTO_TCP, "e", 0);	/* no expiry */
	/* an IPv6 pinhole is not a port mapping */
	add_map(7, 6000, "2001:db8::1", 6000, IPPROTO_TCP, "f", 50);

	n = memmap_expired_maps(100, expired, EXPIRE_MAX_PER_PASS, &next);
	assert(n == 2);
	for(i = 0; i < n; i++)
		assert((expired[i].eport == 40001 && expired[i].proto == IPPROTO_TCP) ||
		       (expired[i].eport == 40002 && expired[i].proto == IPPROTO_UDP));
	assert(next == 120);

	/* the rows stay until the rules are gone */
	assert(memmap_expired_maps(100, expired, EXPIRE_MAX_PER_PASS, &next) == 2);
	drop_map(40001, IPPROTO_TCP);
	drop_map(40002, IPPROTO_UDP);
	assert(memmap_expired_maps(100, expired, EXPIRE_MAX_PER_PASS, &next) == 0);
	assert(next == 120);
	lease_table_clear();

	/* more than a pass takes : the next pass is now */
	for(i = 0; i < 3 * EXPIRE_MAX_PER_PASS; i++)
		add_map(0, (unsigned short)(30000 + i), "192.0.2.20", (unsigned short)(1000 + i),
		        IPPROTO_UDP, "x", 10);
	n = memmap_expired_maps(100, expired, EXPIRE_MAX_PER_PASS, &next);
	assert(n == EXPIRE_MAX_PER_PASS && next == 100);
	/* a smaller max is kept */
	assert(memmap_expired_maps(100, expired, 3, &next) == 3 && next == 100);
	lease_table_clear();
}

/* what memmap_each_map_counters() reported */
static struct fake_rule seen[4];
static int seen_count;

static void
see_counters(unsigned short eport, int proto, u_int64_t packets, u_int64_t bytes,
             void * arg)
{
	UNUSED(arg);
	assert(seen_count < 4);
	seen[seen_count].eport = eport;
	seen[seen_count].proto = proto;
	seen[seen_count].packets = packets;
	seen[seen_count].bytes = bytes;
	seen_count++;
}

static void
test_each_map_counters(void)
{
	lease_table_clear();
	add_map(0, 40001, "192.0.2.10", 5000, IPPROTO_TCP, "a", 0);
	add_map(0, 40002, "192.0.2.10", 5001, IPPROTO_UDP, "b", 0);	/* its rule is gone */
	add_map(7, 6000, "2001:db8::1", 6000, IPPROTO_TCP, "c", 0);	/* not a port mapping */
	/* NAT-PMP and PCP: their lease ends them, not their counters */
	add_map(0, 40004, "192.0.2.11", 5002, IPPROTO_TCP, "NAT-PMP 40004 tcp", 0);
	add_map(0, 40005, "192.0.2.12", 5003, IPPROTO_TCP, PCP_DESC, 0);
	fake_rules[0].eport = 40001;
	fake_rules[0].proto = IPPROTO_TCP;
	fake_rules[0].packets = 5;
	fake_rules[0].bytes = 500;
	fake_rules[1].eport = 40003;	/* a rule with no row */
	fake_rules[1].proto = IPPROTO_TCP;
	fake_rules[1].packets = 9;
	fake_rules[1].bytes = 900;
	fake_rules[2].eport = 40004;
	fake_rules[2].proto = IPPROTO_TCP;
	fake_rules[3].eport = 40005;
	fake_rules[3].proto = IPPROTO_TCP;
	fake_rule_count = 4;
	fake_reads = 0;
	seen_count = 0;

	assert(memmap_each_map_counters(see_counters, NULL) == 0);
	assert(seen_count == 1);
	assert(seen[0].eport == 40001 && seen[0].proto == IPPROTO_TCP);
	assert(seen[0].packets == 5 && seen[0].bytes == 500);
	/* a firewall which can list its rules is read once, not once a mapping */
#if defined(USE_NETFILTER) && !defined(USE_NFTABLES)
	assert(fake_reads == 1);
#elif defined(USE_PF)
	assert(fake_reads == fake_rule_count + 1);
#else
	assert(fake_reads == 2);
#endif
	fake_rule_count = 0;
	lease_table_clear();
}

#ifdef TEST_PINHOLES
/* One expiry pass over the pinholes at time now, in which the firewall removes
 * "removed" rules (< 0 : it fails). */
static void
expire_pinholes(time_t now, int removed)
{
	unsigned int next;

	fake_now = now;
	fake_removed = removed;
	(void)memmap_expire_pinholes(&next);
}

static void
test_pinhole_expiry(void)
{
	char iaddr[64];
	unsigned int i;

	lease_table_clear();
	add_map(1, 6001, "2001:db8::1", 6001, IPPROTO_TCP, "a", 90);	/* expired */
	add_map(2, 6002, "2001:db8::1", 6002, IPPROTO_TCP, "b", 150);
	add_map(3, 6003, "2001:db8::1", 6003, IPPROTO_TCP, "c", 0);	/* no expiry */
	assert(lease_table_count() == 3);

	/* the firewall failed : the rows stay */
	expire_pinholes(100, -1);
	assert(lease_table_count() == 3);

	/* a pass which leaves expired rules keeps the rows, once */
	fake_partial = 1;
	expire_pinholes(100, 1);
	assert(lease_table_count() == 3);

	/* a full pass removes the expired row only */
	expire_pinholes(100, 1);
	assert(lease_table_count() == 2);
	assert(lease_table_find_uid(1) == NULL);
	assert(lease_table_find_uid(2) != NULL && lease_table_find_uid(3) != NULL);

	/* a renewal by uid moves the expiry */
	renew_uid(2, 300);
	expire_pinholes(200, 1);
	assert(lease_table_count() == 2);
	expire_pinholes(300, 1);
	assert(lease_table_count() == 1);

	/* a full pass which removed no rule : the rule of the expired row was
	 * already gone, and the row goes too */
	add_map(4, 6004, "2001:db8::1", 6004, IPPROTO_TCP, "d", 350);
	expire_pinholes(400, 0);
	assert(lease_table_count() == 1);
	assert(lease_table_find_uid(4) == NULL);
	lease_table_clear();

	/* more expired pinholes than one walk takes; an IPv4 mapping is not a
	 * pinhole, whatever its expiry */
	for(i = 0; i < 600; i++) {
		snprintf(iaddr, sizeof(iaddr), "2001:db8::%x", i + 1);
		add_map((unsigned short)(i + 1), 0, iaddr, 8080, IPPROTO_UDP, "upnp", 100);
	}
	add_map(1000, 0, "2001:db8:1::1", 8080, IPPROTO_UDP, "upnp", 101);
	add_map(1001, 0, "2001:db8:1::2", 8080, IPPROTO_UDP, "upnp", 0);
	add_map(0, 40001, "192.0.2.10", 8080, IPPROTO_TCP, "web", 50);
	assert(lease_table_count() == 603);

	expire_pinholes(99, 600);
	assert(lease_table_count() == 603);
	expire_pinholes(100, 600);
	assert(lease_table_count() == 3);
	assert(lease_table_find_uid(1) == NULL && lease_table_find_uid(600) == NULL);
	assert(lease_table_find_uid(1000) != NULL);
	expire_pinholes(101, 1);
	assert(lease_table_find_uid(1000) == NULL);
	/* 0 : no expiry */
	expire_pinholes(0x7fffffff, 1);
	assert(lease_table_find_uid(1001) != NULL);
	assert(lease_table_find_mapping(IPPROTO_TCP, AF_INET, NULL, 40001) != NULL);
	assert(lease_table_count() == 2);
	lease_table_clear();
}
#endif /* TEST_PINHOLES */

int
main(void)
{
	test_ipv4();
	test_ipv6();
	test_find_map();
	test_one_port_many_clients();
	test_expired_maps();
	test_each_map_counters();
#ifdef TEST_PINHOLES
	test_pinhole_expiry();
#endif
	printf("testmemmap: all tests passed\n");
	return 0;
}
