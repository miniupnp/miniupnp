/* Unit test of the rule by rule fw_sync() of fwsync.c: a failure takes back
 * the changes before it, and a change whose rule had no row is not taken back
 * from a made up rule. The backend functions are fakes which record their
 * calls, with the prototypes of the firewall the tree is configured for
 * (iptables, nftables, pf, ipf or ipfw):
 *
 *   cc -fsanitize=address,undefined -o testfwsync testfwsync.c fwsync.c
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "config.h"
#include "fwsync.h"

const char * ext_if_name = "wan";
const char * ext_if_name6 = "wan";

static int fail_add_redirect;	/* add_redirect_rule2() call number N fails */
static int redirect_calls;
static int adds, deletes, updates;
static unsigned short last_update_iport;
static int update_with_port_zero;
static int fail_delete;		/* delete_redirect_and_filter_rules() fails */
static int rule_present;	/* 1: get_redirect_rule() finds the rule, 0: not, -1: an error */

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
	return 0;
}

/* a delete of the rules of a port, which fails on demand */
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
	if(iport == 0)
		update_with_port_zero = 1;
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

/* the pinhole functions, which these tests do not reach */
#define WEAK __attribute__((weak))
#ifdef FW_MAP6
/* the remote of the last IPv6 allow rule added: "(any)" for NULL */
static char map6_rhost[64];
static unsigned short map6_rport;
WEAK int add_map6_rule(const char * ifname, const char * rem_host, unsigned short rem_port,
                       const char * int_client, unsigned short int_port, int proto,
                       const char * desc, unsigned int timestamp)
{ (void)ifname; (void)int_client; (void)int_port; (void)proto; (void)desc; (void)timestamp;
  snprintf(map6_rhost, sizeof(map6_rhost), "%s", rem_host ? rem_host : "(any)");
  map6_rport = rem_port;
  return 0; }
WEAK int update_map6_rule(const char * ifname, const char * rem_host, unsigned short rem_port,
                             const char * int_client, unsigned short int_port, int proto,
                             const char * desc, unsigned int timestamp)
{ (void)ifname; (void)rem_host; (void)rem_port; (void)int_client; (void)int_port;
  (void)proto; (void)desc; (void)timestamp; return -1; }
static int map6_delete_result = -1;	/* what delete_map6_rule() answers */
WEAK int delete_map6_rule(const char * rem_host, unsigned short rem_port,
                             const char * int_client, unsigned short int_port, int proto)
{ (void)rem_host; (void)rem_port; (void)int_client; (void)int_port; (void)proto;
  return map6_delete_result; }
#endif

static void
row(struct lease_entry * e, unsigned short eport, unsigned short iport)
{
	memset(e, 0, sizeof(*e));
	e->family = AF_INET;
	e->proto = IPPROTO_TCP;
	e->eport = eport;
	e->iport = iport;
	e->iaddr.s6_addr[10] = e->iaddr.s6_addr[11] = 0xff;
	e->iaddr.s6_addr[12] = 192;
	e->iaddr.s6_addr[15] = 10;
	e->label = "test";
}

static void
reset(void)
{
	fail_add_redirect = 0;
	redirect_calls = 0;
	adds = deletes = updates = 0;
	last_update_iport = 0;
	update_with_port_zero = 0;
	fail_delete = 0;
	rule_present = 0;
}

/* an add which fails takes back the add before it */
static void
test_add_undone(void)
{
	struct lease_entry a, b;
	struct fw_change c[2];
	reset();
	row(&a, 1000, 80);
	row(&b, 1001, 81);
	memset(c, 0, sizeof(c));
	c[0].op = FW_ADD; c[0].row = &a;
	c[1].op = FW_ADD; c[1].row = &b;
	fail_add_redirect = 2;
	assert(fw_sync(c, 2) < 0);
	assert(adds == 1 && deletes == 1);
	assert(c[0].applied == FW_NOT_APPLIED && c[1].applied == FW_NOT_APPLIED);
	reset();
	assert(fw_sync(c, 2) == 0 && adds == 2);
	assert(c[0].applied == FW_APPLIED && c[1].applied == FW_APPLIED);
}

/* an update of a rule with a row is taken back to the old rule */
static void
test_update_undone(void)
{
	struct lease_entry old, new, add;
	struct fw_change c[2];
	reset();
	row(&old, 1000, 80);
	row(&new, 1000, 8080);
	row(&add, 1001, 81);
	memset(c, 0, sizeof(c));
	c[0].op = FW_UPDATE; c[0].old = &old; c[0].row = &new;
	c[1].op = FW_ADD; c[1].row = &add;
	fail_add_redirect = 1;
	assert(fw_sync(c, 2) < 0);
	/* the update and its take back */
	assert(updates == 2 && last_update_iport == 80);
	assert(c[0].applied == FW_NOT_APPLIED && c[1].applied == FW_NOT_APPLIED);
}

/* an update of a rule with no row cannot be taken back: it stays, and is not
 * rewritten from the key with internal port 0 */
static void
test_update_partial_stays(void)
{
	struct lease_entry key, new, add;
	struct fw_change c[2];
	reset();
	memset(&key, 0, sizeof(key));
	key.family = AF_INET;
	key.proto = IPPROTO_TCP;
	key.eport = 1000;
	row(&new, 1000, 8080);
	row(&add, 1001, 81);
	memset(c, 0, sizeof(c));
	c[0].op = FW_UPDATE; c[0].old = &key; c[0].old_partial = 1; c[0].row = &new;
	c[1].op = FW_ADD; c[1].row = &add;
	fail_add_redirect = 1;
	assert(fw_sync(c, 2) < 0);
	assert(updates == 1 && !update_with_port_zero);
	assert(c[0].applied == FW_APPLIED);
}

/* a delete of a rule with no row cannot be taken back: no rule is added from
 * a key which has no internal address */
static void
test_delete_partial_stays(void)
{
	struct lease_entry key, add;
	struct fw_change c[2];
	reset();
	memset(&key, 0, sizeof(key));
	key.family = AF_INET;
	key.proto = IPPROTO_TCP;
	key.eport = 1000;
	row(&add, 1001, 81);
	memset(c, 0, sizeof(c));
	c[0].op = FW_DELETE; c[0].old = &key; c[0].old_partial = 1;
	c[1].op = FW_ADD; c[1].row = &add;
	fail_add_redirect = 1;
	assert(fw_sync(c, 2) < 0);
	assert(deletes == 1 && adds == 0);
	assert(c[0].applied == FW_APPLIED);
}

/* a delete of a rule with a row is taken back by adding it again */
static void
test_delete_undone(void)
{
	struct lease_entry old, add;
	struct fw_change c[2];
	reset();
	row(&old, 1000, 80);
	row(&add, 1001, 81);
	memset(c, 0, sizeof(c));
	c[0].op = FW_DELETE; c[0].old = &old;
	c[1].op = FW_ADD; c[1].row = &add;
	fail_add_redirect = 1;
	assert(fw_sync(c, 2) < 0);
	assert(deletes == 1 && adds == 1);
	assert(c[0].applied == FW_NOT_APPLIED);
}

/* a delete which fails on a rule the firewall does not have lets the row go;
 * one which fails on a rule the firewall still has does not */
static void
test_delete_lost_rule(void)
{
	struct lease_entry old;
	struct fw_change c;
	reset();
	row(&old, 1000, 80);
	memset(&c, 0, sizeof(c));
	c.op = FW_DELETE; c.old = &old;
	fail_delete = 1;
	assert(fw_sync(&c, 1) == 0);
	assert(c.applied == FW_APPLIED);
	rule_present = 1;
	assert(fw_sync(&c, 1) < 0);
	assert(c.applied == FW_NOT_APPLIED);
	/* a firewall which cannot be read is not one without the rule: the row
	 * stays */
	rule_present = -1;
	assert(fw_sync(&c, 1) < 0);
	assert(c.applied == FW_NOT_APPLIED);
	/* with no row, the port is not mapped: the error of the backend stays */
	rule_present = 0;
	c.old_partial = 1;
	assert(fw_sync(&c, 1) < 0);
	assert(c.applied == FW_NOT_APPLIED);
}

#ifdef FW_MAP6
/* an IPv6 allow rule with a remote port and any remote host keeps its port: the rule
 * must not take traffic from every source port */
static void
test_map6_remote_port(void)
{
	struct lease_entry e;
	struct lease_remote r;
	struct fw_change c;
	reset();
	memset(&e, 0, sizeof(e));
	e.family = AF_INET6;
	e.proto = IPPROTO_UDP;
	e.eport = e.iport = 8080;
	e.iaddr.s6_addr[0] = 0x20;
	e.iaddr.s6_addr[15] = 0x10;
	e.eaddr = e.iaddr;
	e.label = "test";
	memset(&r, 0, sizeof(r));	/* :: : any remote host */
	r.rport = 5000;
	e.remote = &r;
	memset(&c, 0, sizeof(c));
	c.op = FW_ADD; c.row = &e;
	assert(fw_sync(&c, 1) == 0);
	assert(strcmp(map6_rhost, "(any)") == 0 && map6_rport == 5000);
	/* a remote host too */
	r.raddr.s6_addr[0] = 0x20;
	r.raddr.s6_addr[15] = 0x05;
	assert(fw_sync(&c, 1) == 0);
	assert(strcmp(map6_rhost, "2000::5") == 0 && map6_rport == 5000);
}

/* the label a map6 rule gets reads back as its description, and so do the
 * labels of older daemons; another program's label is not the daemon's */
static void
test_map6_label(void)
{
	char label[64];
	map6_label(label, sizeof(label), "game");
	assert(strcmp(label, "pinhole: game") == 0);
	assert(strcmp(map6_label_desc(label), "game") == 0);
	assert(strcmp(map6_label_desc("pinhole-12 ts-34: old"), "old") == 0);
	assert(map6_label_desc("other: x") == NULL);
}

/* an IPv6 delete of a rule the firewall does not have (-2) lets the row go;
 * any other failure, or no row, keeps the error */
static void
test_delete_lost_map6(void)
{
	struct lease_entry old;
	struct fw_change c;
	reset();
	row(&old, 1000, 80);
	old.family = AF_INET6;
	memset(&old.iaddr, 0, sizeof(old.iaddr));
	old.iaddr.s6_addr[0] = 0x20;
	old.iaddr.s6_addr[1] = 0x01;
	old.iaddr.s6_addr[15] = 1;
	memset(&c, 0, sizeof(c));
	c.op = FW_DELETE; c.old = &old;
	map6_delete_result = -2;
	assert(fw_sync(&c, 1) == 0);
	assert(c.applied == FW_APPLIED);
	map6_delete_result = -1;
	assert(fw_sync(&c, 1) < 0);
	assert(c.applied == FW_NOT_APPLIED);
	map6_delete_result = -2;
	c.old_partial = 1;
	assert(fw_sync(&c, 1) < 0);
	assert(c.applied == FW_NOT_APPLIED);
	map6_delete_result = -1;
}
#endif

int
main(void)
{
	test_add_undone();
	test_update_undone();
	test_update_partial_stays();
	test_delete_partial_stays();
	test_delete_undone();
	test_delete_lost_rule();
#ifdef FW_MAP6
	test_map6_remote_port();
	test_map6_label();
	test_delete_lost_map6();
#endif
	printf("testfwsync: all tests passed\n");
	return 0;
}
