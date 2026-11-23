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

const char * ext_if_name = "wan";

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
int
delete_redirect_rule(const char * ifname, unsigned short eport, int proto)
{
	(void)ifname; (void)eport; (void)proto;
	return fake_delete();
}
#endif

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

/* a failed filter rule: the add fails, and on netfilter its redirect rule
 * stays, as a half applied change */
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
#if defined(__linux__)
	CHECK(c.applied == FW_HALF_APPLIED);
#else
	CHECK(c.applied == FW_NOT_APPLIED);
	CHECK(deletes == 1);
#endif
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
	if(failures) {
		fprintf(stderr, "testfwsync: %d check(s) failed\n", failures);
		return 1;
	}
	printf("testfwsync: all tests passed\n");
	return 0;
}
