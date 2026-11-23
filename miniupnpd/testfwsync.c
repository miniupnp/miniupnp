/* MiniUPnP project
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

/* Unit test of fw_sync() (fwsync.c): a request applies whole, or a failure
 * takes back the changes before it. The backend functions are fakes which
 * count their calls, with the prototypes of the firewall the tree is
 * configured for. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "config.h"
#include "commonrdr.h"
#include "fwsync.h"

const char * ext_if_name = "wan";
const char * ext_if_name6 = "wan";

static int fail_add_redirect;	/* add_redirect_rule2() call number N fails */
static int redirect_calls;
static int fail_add_filter;	/* add_filter_rule2() fails */
static int fail_delete;		/* the deletes fail */
static int rule_present;	/* get_redirect_rule(): 1 the rule, 0 none, -1 an error */
static int adds, deletes, updates;
static unsigned short last_update_iport;

static int failures;

/* upnputils.c, without the globals of the daemon it needs */
const char *
proto_itoa(int proto)
{
	return proto == IPPROTO_UDP ? "UDP" : "TCP";
}

#define CHECK(cond) do { if(!(cond)) { \
	fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #cond); \
	failures++; } } while(0)

int
add_redirect_rule2(const char * ifname, const char * rhost, unsigned short eport,
                   const char * iaddr, unsigned short iport, int proto,
                   const char * desc, unsigned int timestamp)
{
	(void)ifname; (void)rhost; (void)eport; (void)iaddr; (void)iport;
	(void)proto; (void)desc; (void)timestamp;
	if(++redirect_calls == fail_add_redirect)
		return -1;
	adds++;
	return 0;
}

int
add_filter_rule2(const char * ifname, const char * rhost, const char * iaddr,
                 unsigned short eport, unsigned short iport, int proto,
                 const char * desc)
{
	(void)ifname; (void)rhost; (void)iaddr; (void)eport; (void)iport;
	(void)proto; (void)desc;
	return fail_add_filter ? -1 : 0;
}

static int
fake_delete(void)
{
	if(fail_delete)
		return -1;
	deletes++;
	return 0;
}

#if defined(__linux__)
int
delete_redirect_and_filter_rules(unsigned short eport, int proto)
{
	(void)eport; (void)proto;
	return fake_delete();
}
#else
#if defined(USE_PF)
int
delete_redirect_and_filter_rules(const char * ifname, unsigned short eport, int proto)
{
	(void)ifname; (void)eport; (void)proto;
	return fake_delete();
}
#else
int
delete_filter_rule(const char * ifname, unsigned short eport, int proto)
{
	(void)ifname; (void)eport; (void)proto;
	return 0;
}
#endif
#endif

int
delete_redirect_rule(const char * ifname, unsigned short eport, int proto)
{
	(void)ifname; (void)eport; (void)proto;
	return fake_delete();
}

int
get_redirect_rule(const char * ifname, unsigned short eport, int proto,
                  char * iaddr, int iaddrlen, unsigned short * iport,
                  char * desc, int desclen, char * rhost, int rhostlen,
                  unsigned int * timestamp, u_int64_t * packets, u_int64_t * bytes)
{
	(void)ifname; (void)eport; (void)proto; (void)iaddr; (void)iaddrlen; (void)iport;
	(void)desc; (void)desclen; (void)rhost; (void)rhostlen; (void)timestamp;
	(void)packets; (void)bytes;
	return rule_present > 0 ? 0 : rule_present == 0 ? -2 : -1;
}

/* the firewall has the rules of ports 5000 and 5001, with counters */
#define FAKE_RULES	2

#if defined(USE_IPTABLES)
int
get_redirect_rules_counters(void (*fn)(unsigned short eport, int proto,
                                       u_int64_t packets, u_int64_t bytes, void * arg),
                            void * arg)
{
	int i;
	for(i = 0; i < FAKE_RULES; i++)
		fn((unsigned short)(5000 + i), IPPROTO_TCP, (u_int64_t)(10 * i), (u_int64_t)(100 * i), arg);
	return 0;
}
#endif

int
get_redirect_rule_by_index(int index, char * ifname, unsigned short * eport,
                           char * iaddr, int iaddrlen, unsigned short * iport,
                           int * proto, char * desc, int desclen,
                           char * rhost, int rhostlen, unsigned int * timestamp,
                           u_int64_t * packets, u_int64_t * bytes)
{
	(void)ifname; (void)iaddr; (void)iaddrlen; (void)desc; (void)desclen;
	(void)rhost; (void)rhostlen;
	if(index >= FAKE_RULES)
		return -1;
	*eport = (unsigned short)(5000 + index);
	*iport = *eport;
	*proto = IPPROTO_TCP;
	*timestamp = 0;
	*packets = (u_int64_t)(10 * index);
	*bytes = (u_int64_t)(100 * index);
	return 0;
}

int
update_portmapping(const char * ifname, unsigned short eport, int proto,
                   unsigned short iport, const char * desc, unsigned int timestamp)
{
	(void)ifname; (void)eport; (void)proto; (void)desc; (void)timestamp;
	updates++;
	last_update_iport = iport;
	return 0;
}

int
update_portmapping_desc_timestamp(const char * ifname, unsigned short eport, int proto,
                                  const char * desc, unsigned int timestamp)
{
	(void)ifname; (void)eport; (void)proto; (void)desc; (void)timestamp;
	updates++;
	return 0;
}

#if defined(PCP_PEER) && defined(USE_NETFILTER)
static int peer_adds, fail_peer_add;
static int peer_present;	/* get_peer_rule_by_index() lists the PEER rule */

int
add_peer_redirect_rule2(const char * ifname, const char * rhost, unsigned short rport,
                        const char * eaddr, unsigned short eport,
                        const char * iaddr, unsigned short iport, int proto,
                        const char * desc, unsigned int timestamp)
{
	(void)ifname; (void)rhost; (void)rport; (void)eaddr; (void)eport;
	(void)iaddr; (void)iport; (void)proto; (void)desc; (void)timestamp;
	if(peer_adds + 1 == fail_peer_add)
		return -1;
	peer_adds++;
	return 0;
}

/* the PEER rule of each key goes, or is not there (peer_present 0) */
int
outgoing_rule_delete(struct outgoing_rule_key * keys, int n)
{
	int i;

	if(fail_delete)
		return -1;
	for(i = 0; i < n; i++) {
		keys[i].result = peer_present ? 0 : -2;
		if(peer_present)
			deletes++;
	}
	peer_present = 0;
	return 0;
}

int
add_peer_dscp_rule2(const char * ifname, const char * rhost, unsigned short rport,
                    unsigned char dscp, const char * iaddr, unsigned short iport,
                    int proto, const char * desc, unsigned int timestamp)
{
	(void)ifname; (void)rhost; (void)rport; (void)dscp; (void)iaddr;
	(void)iport; (void)proto; (void)desc; (void)timestamp;
	return 0;
}

int
get_peer_rule_by_index(int index, char * ifname, unsigned short * eport,
                       char * iaddr, int iaddrlen, unsigned short * iport,
                       int * proto, char * desc, int desclen,
                       char * rhost, int rhostlen, unsigned short * rport,
                       unsigned int * timestamp, u_int64_t * packets, u_int64_t * bytes)
{
	(void)ifname; (void)iaddr; (void)iaddrlen; (void)desc; (void)desclen;
	(void)rhost; (void)rhostlen; (void)timestamp; (void)packets; (void)bytes;
	if(index > 0 || !peer_present)
		return -1;
	*eport = 6000;
	*iport = 5000;
	*proto = IPPROTO_UDP;
	*rport = 7000;
	return 0;
}
#endif

#ifdef FW_MAP6
static int map6_adds, map6_deletes, fail_map6_add_at, map6_gone;

int
add_map6_rule(const char * ifname, const char * rem_host, unsigned short rem_port,
              const char * int_client, unsigned short int_port,
              int proto, const char * desc, unsigned int timestamp)
{
	(void)ifname; (void)rem_host; (void)rem_port; (void)int_client;
	(void)int_port; (void)proto; (void)desc; (void)timestamp;
	if(map6_adds + 1 == fail_map6_add_at)
		return -1;
	map6_adds++;
	return 0;
}

int
update_map6_rule(const char * ifname, const char * rem_host, unsigned short rem_port,
                 const char * int_client, unsigned short int_port,
                 int proto, const char * desc, unsigned int timestamp)
{
	(void)ifname; (void)rem_host; (void)rem_port; (void)int_client;
	(void)int_port; (void)proto; (void)desc; (void)timestamp;
	return 0;
}

/* the first map6_gone deletes find no rule (-2) */
int
delete_map6_rule(const char * rem_host, unsigned short rem_port,
                 const char * int_client, unsigned short int_port, int proto)
{
	(void)rem_host; (void)rem_port; (void)int_client; (void)int_port; (void)proto;
	if(map6_gone > 0) {
		map6_gone--;
		return -2;
	}
	if(fail_delete)
		return -1;
	map6_deletes++;
	return 0;
}

int
get_map6_packets(const char * rem_host, unsigned short rem_port,
                 const char * int_client, unsigned short int_port,
                 int proto, u_int64_t * packets)
{
	(void)rem_host; (void)rem_port; (void)int_client; (void)int_port; (void)proto;
	*packets = 0;
	return 0;
}
#endif

static void
reset(void)
{
	fail_add_redirect = 0;
	redirect_calls = 0;
	fail_add_filter = 0;
	fail_delete = 0;
	rule_present = 1;
	adds = deletes = updates = 0;
	last_update_iport = 0;
#ifdef FW_MAP6
	map6_adds = map6_deletes = fail_map6_add_at = map6_gone = 0;
#endif
#if defined(PCP_PEER) && defined(USE_NETFILTER)
	peer_adds = 0;
	fail_peer_add = 0;
	peer_present = 1;
#endif
}

/* an IPv4 UPnP port mapping 192.168.1.<host>:iport <- eport */
static void
mapping(struct lease_entry * e, int host, unsigned short eport, unsigned short iport)
{
	char a[32];
	int family = AF_INET;

	lease_entry_init(e, MAP_KIND_UPNP, NULL);
	snprintf(a, sizeof(a), "192.168.1.%d", host);
	map_pton(a, &family, &e->iaddr);
	e->family = (unsigned char)family;
	e->proto = IPPROTO_TCP;
	e->eport = eport;
	e->iport = iport;
	e->label = "test";
}

/* one add, applied */
static void
test_add(void)
{
	struct lease_entry e;
	struct fw_change c;

	reset();
	mapping(&e, 10, 5000, 5000);
	fw_change_init(&c, FW_ADD, &e, NULL);
	CHECK(fw_sync(&c, 1) == 0);
	CHECK(c.applied == FW_APPLIED);
	CHECK(adds == 1);
}

/* the second add fails: the first is taken back */
static void
test_add_fails_takes_back(void)
{
	struct lease_entry a, b;
	struct fw_change c[2];

	reset();
	mapping(&a, 10, 5000, 5000);
	mapping(&b, 11, 5001, 5001);
	fw_change_init(&c[0], FW_ADD, &a, NULL);
	fw_change_init(&c[1], FW_ADD, &b, NULL);
	fail_add_redirect = 2;
	CHECK(fw_sync(c, 2) < 0);
	CHECK(c[0].applied == FW_NOT_APPLIED);
	CHECK(c[1].applied == FW_NOT_APPLIED);
	CHECK(adds == 1 && deletes == 1);
}

/* the first add cannot be taken back: it stays applied */
static void
test_take_back_fails(void)
{
	struct lease_entry a, b;
	struct fw_change c[2];

	reset();
	mapping(&a, 10, 5000, 5000);
	mapping(&b, 11, 5001, 5001);
	fw_change_init(&c[0], FW_ADD, &a, NULL);
	fw_change_init(&c[1], FW_ADD, &b, NULL);
	fail_add_redirect = 2;
	fail_delete = 1;
	rule_present = -1;	/* the firewall cannot be read */
	CHECK(fw_sync(c, 2) < 0);
	CHECK(c[0].applied == FW_APPLIED);
	CHECK(c[1].applied == FW_NOT_APPLIED);
}

/* an update, then a failed add: the update goes back to the old rule */
static void
test_update_taken_back(void)
{
	struct lease_entry old, upd, b;
	struct fw_change c[2];

	reset();
	mapping(&old, 10, 5000, 5000);
	mapping(&upd, 10, 5000, 6000);
	mapping(&b, 11, 5001, 5001);
	fw_change_init(&c[0], FW_UPDATE, &upd, &old);
	fw_change_init(&c[1], FW_ADD, &b, NULL);
	fail_add_redirect = 1;
	CHECK(fw_sync(c, 2) < 0);
	CHECK(c[0].applied == FW_NOT_APPLIED);
	CHECK(updates == 2);
	CHECK(last_update_iport == 5000);
}

/* a failed filter rule: the add fails, and its redirect rule goes again. If
 * that delete fails too, the redirect rule stays, as a half applied
 * change. */
static void
test_filter_fails(void)
{
	struct lease_entry e;
	struct fw_change c;

	reset();
	mapping(&e, 10, 5000, 5000);
	fw_change_init(&c, FW_ADD, &e, NULL);
	c.fresh = 1;
	fail_add_filter = 1;
	CHECK(fw_sync(&c, 1) < 0);
	CHECK(c.applied == FW_NOT_APPLIED);
	CHECK(deletes == 1);

	reset();
	fw_change_init(&c, FW_ADD, &e, NULL);
	c.fresh = 1;
	fail_add_filter = 1;
	fail_delete = 1;
	CHECK(fw_sync(&c, 1) < 0);
	CHECK(c.applied == FW_HALF_APPLIED);
}

/* A delete of a rule the firewall lost succeeds, so the row can go; with a
 * firewall which cannot be read it fails, and the row stays. */
static void
test_delete_lost_rule(void)
{
	struct lease_entry e;
	struct fw_change c;

	reset();
	mapping(&e, 10, 5000, 5000);
	fw_change_init(&c, FW_DELETE, NULL, &e);
	fail_delete = 1;
	rule_present = 0;
	CHECK(fw_sync(&c, 1) == 0);
	CHECK(c.applied == FW_APPLIED);

	reset();
	fw_change_init(&c, FW_DELETE, NULL, &e);
	fail_delete = 1;
	rule_present = -1;
	CHECK(fw_sync(&c, 1) < 0);
	CHECK(c.applied == FW_NOT_APPLIED);
}

/* a delete, then a failed add: the deleted rules are added again */
static void
test_delete_taken_back(void)
{
	struct lease_entry old, b;
	struct fw_change c[2];

	reset();
	mapping(&old, 10, 5000, 5000);
	mapping(&b, 11, 5001, 5001);
	fw_change_init(&c[0], FW_DELETE, NULL, &old);
	fw_change_init(&c[1], FW_ADD, &b, NULL);
	fail_add_redirect = 1;
	CHECK(fw_sync(c, 2) < 0);
	CHECK(deletes == 1);
	CHECK(adds == 1);	/* the rule of old, back */
	CHECK(c[0].applied == FW_NOT_APPLIED);
}

#if defined(PCP_PEER) && defined(USE_NETFILTER)
/* a PEER binding 192.168.1.10:5000 -> 203.0.113.1:6000 to 198.51.100.7:7000 */
static void
binding(struct outgoing_entry * b, struct outgoing_peer * p)
{
	int family;

	memset(b, 0, sizeof(*b));
	memset(p, 0, sizeof(*p));
	b->family = AF_INET;
	b->proto = IPPROTO_UDP;
	map_pton("192.168.1.10", &family, &b->iaddr);
	map_pton("203.0.113.1", &family, &b->eaddr);
	b->iport = 5000;
	b->eport = 6000;
	map_pton("198.51.100.7", &family, &p->raddr);
	p->rport = 7000;
	b->peers = p;
	b->npeers = 1;
}

/* A PEER add, a delete of a PEER rule the firewall lost, which succeeds,
 * and a delete the firewall refuses. */
static void
test_peer(void)
{
	struct outgoing_entry b;
	struct outgoing_peer p;
	struct fw_out_change c;

	reset();
	binding(&b, &p);
	fw_out_change_init(&c, FW_OUT_ADD, &b, 0);
	CHECK(fw_sync_out(&c, 1) == 0);
	CHECK(peer_adds == 1);

	reset();
	fw_out_change_init(&c, FW_OUT_DELETE, &b, 0);
	peer_present = 0;
	CHECK(fw_sync_out(&c, 1) == 0);
	CHECK(deletes == 0);

	reset();
	fw_out_change_init(&c, FW_OUT_DELETE, &b, 0);
	fail_delete = 1;
	CHECK(fw_sync_out(&c, 1) < 0);
	CHECK(c.applied == FW_NOT_APPLIED);
}

/* two PEER adds, the second fails: the first goes again */
static void
test_peer_taken_back(void)
{
	struct outgoing_entry b;
	struct outgoing_peer p;
	struct fw_out_change c[2];

	reset();
	binding(&b, &p);
	fw_out_change_init(&c[0], FW_OUT_ADD, &b, 0);
	fw_out_change_init(&c[1], FW_OUT_ADD, &b, 0);
	fail_peer_add = 2;
	CHECK(fw_sync_out(c, 2) < 0);
	CHECK(peer_adds == 1 && deletes == 1);
	CHECK(c[0].applied == FW_NOT_APPLIED);
}
#endif

static void
count_rule(unsigned short eport, int proto, u_int64_t packets, u_int64_t bytes, void * arg)
{
	int * n = arg;
	CHECK(proto == IPPROTO_TCP);
	CHECK(packets == (u_int64_t)(10 * (eport - 5000)));
	CHECK(bytes == (u_int64_t)(100 * (eport - 5000)));
	(*n)++;
}

/* the counters of every rule, once each */
static void
test_each_map_counters(void)
{
	int n = 0;

	CHECK(fw_each_map_counters(count_rule, &n) == 0);
	CHECK(n == FAKE_RULES);
}

#ifdef FW_MAP6
#define MAP6_FILTERS	300	/* a PCP MAP can carry hundreds of FILTER options */

/* an IPv6 map [2001:db8::10]:5000 with n filters, one per remote */
static void
map6(struct lease_entry * e, struct map_filter * f, int n)
{
	char a[64];
	int i, family;

	lease_entry_init(e, MAP_KIND_PCP, NULL);
	e->family = AF_INET6;
	e->proto = IPPROTO_UDP;
	map_pton("2001:db8::10", &family, &e->iaddr);
	e->eaddr = e->iaddr;
	e->iport = e->eport = 5000;
	for(i = 0; i < n; i++) {
		memset(&f[i], 0, sizeof(f[i]));
		snprintf(a, sizeof(a), "2001:db8:1::%x", i + 1);
		map_pton(a, &family, &f[i].raddr);
		f[i].prefix = 128;
	}
	e->filters = f;
	e->nfilters = n;
}

/* The rules of every filter go in one change, all or nothing; a delete
 * counts a rule which is gone already as deleted. */
static void
test_map6_filters(void)
{
	static struct map_filter f[MAP6_FILTERS];
	struct lease_entry e;
	struct fw_change c;

	reset();
	map6(&e, f, MAP6_FILTERS);
	fw_change_init(&c, FW_ADD, &e, NULL);
	CHECK(fw_sync(&c, 1) == 0);
	CHECK(map6_adds == MAP6_FILTERS);

	reset();
	fw_change_init(&c, FW_ADD, &e, NULL);
	fail_map6_add_at = MAP6_FILTERS;	/* the last one */
	CHECK(fw_sync(&c, 1) < 0);
	CHECK(c.applied == FW_NOT_APPLIED);
	CHECK(map6_deletes == MAP6_FILTERS - 1);

	reset();
	fw_change_init(&c, FW_DELETE, NULL, &e);
	map6_gone = 10;
	CHECK(fw_sync(&c, 1) == 0);
	CHECK(map6_deletes == MAP6_FILTERS - 10);
}
#endif

int
main(void)
{
	test_add();
	test_add_fails_takes_back();
	test_take_back_fails();
	test_update_taken_back();
	test_filter_fails();
	test_delete_lost_rule();
	test_delete_taken_back();
	test_each_map_counters();
#ifdef FW_MAP6
	test_map6_filters();
#endif
#if defined(PCP_PEER) && defined(USE_NETFILTER)
	test_peer();
	test_peer_taken_back();
#endif
	if(failures) {
		fprintf(stderr, "testfwsync: %d check(s) failed\n", failures);
		return 1;
	}
	printf("testfwsync: all tests passed\n");
	return 0;
}
