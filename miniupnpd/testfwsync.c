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
#include "fwsync.h"
#include "testfwfake.h"

const char * ext_if_name = "wan";
const char * ext_if_name6 = "wan";

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

/* many adds go FW_BATCH to a fw_sync(); a refused batch goes again change
 * by change, so the add the firewall refused once does not keep the others
 * out */
static void
test_each(void)
{
	static struct lease_entry e[FW_BATCH + 6];
	static struct fw_change c[FW_BATCH + 6];
	const int n = FW_BATCH + 6;
	int i;

	reset();
	for(i = 0; i < n; i++) {
		mapping(&e[i], 10, (unsigned short)(6000 + i), 80);
		fw_change_init(&c[i], FW_ADD, &e[i], NULL);
	}
	CHECK(fw_sync_each(c, n) == 0);
	CHECK(adds == n && deletes == 0);
	/* the third add of the first batch fails: the two before it are taken
	 * back, then the batch goes one by one */
	reset();
	for(i = 0; i < n; i++)
		fw_change_init(&c[i], FW_ADD, &e[i], NULL);
	fail_add_redirect = 3;
	CHECK(fw_sync_each(c, n) == 0);
	for(i = 0; i < n; i++)
		CHECK(c[i].applied == FW_APPLIED);
	CHECK(deletes == 2);
	CHECK(adds == 2 + FW_BATCH + 6);
	/* a change which stayed after a failed take back is not sent twice */
	reset();
	for(i = 0; i < 3; i++)
		fw_change_init(&c[i], FW_ADD, &e[i], NULL);
	fail_add_redirect = 2;
	fail_delete = 1;
	rule_present = -1;
	CHECK(fw_sync_each(c, 3) == 0);
	CHECK(c[0].applied == FW_APPLIED && adds == 3);
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

/* The renewal check of an IPv4 row: there, gone, pointed elsewhere,
 * unreadable, gone for good. */
static void
test_check_row4(void)
{
	struct lease_entry e;

	reset();
	mapping(&e, 10, 5000, 5000);
	CHECK(fw_check_row(&e) == 0 && adds == 0 && deletes == 0);

	reset();
	rule_present = 0;	/* gone: added back */
	CHECK(fw_check_row(&e) == 1 && adds == 1 && deletes == 0);

	reset();
	rule_iaddr = "192.168.1.99";	/* elsewhere: its rule goes, the row's comes */
	CHECK(fw_check_row(&e) == 1 && deletes == 1 && adds == 1);

	reset();
	rule_iport = 6000;	/* another internal port is elsewhere too */
	CHECK(fw_check_row(&e) == 1 && deletes == 1 && adds == 1);

	reset();
	rule_present = -1;	/* unreadable: nothing known, nothing sent */
	CHECK(fw_check_row(&e) == -1 && adds == 0 && deletes == 0);

	reset();
	rule_present = 0;
	fail_add_redirect = 1;	/* gone, and the add fails */
	CHECK(fw_check_row(&e) == -2 && !e.fw_partial);
}

#ifdef FW_MAP6
/* An IPv6 map whose rule is lost: what is left goes, all come back. */
/* An IPv6 map with no filter has one rule, of any remote. */
static void
test_map6_no_filter(void)
{
	struct lease_entry e;
	struct fw_change c;

	reset();
	map6(&e, NULL, 0);
	fw_change_init(&c, FW_ADD, &e, NULL);
	CHECK(fw_sync(&c, 1) == 0 && map6_adds == 1);
	reset();
	fw_change_init(&c, FW_DELETE, NULL, &e);
	CHECK(fw_sync(&c, 1) == 0 && map6_deletes == 1);
}

static void
test_check_row6(void)
{
	static struct map_filter f[3];
	struct lease_entry e;

	reset();
	map6(&e, f, 3);
	CHECK(fw_check_row(&e) == 0 && map6_adds == 0);
	reset();
	map6_lost = 1;
	CHECK(fw_check_row(&e) == 1 && map6_adds == 3);
	/* a map with no filter: its one rule of any remote */
	reset();
	map6(&e, NULL, 0);
	CHECK(fw_check_row(&e) == 0 && map6_adds == 0);
	reset();
	map6_lost = 1;
	CHECK(fw_check_row(&e) == 1 && map6_adds == 1);
}
#endif

int
main(void)
{
	test_add();
	test_add_fails_takes_back();
	test_take_back_fails();
	test_each();
	test_update_taken_back();
	test_filter_fails();
	test_delete_lost_rule();
	test_delete_taken_back();
	test_each_map_counters();
	test_check_row4();
#ifdef FW_MAP6
	test_map6_filters();
	test_map6_no_filter();
	test_check_row6();
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
