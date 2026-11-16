/* Unit test of memmap_sync(): the rows of a request go into the table only
 * when the firewall takes the request, and come out as they were when not.
 * fw_sync() is a fake here, which records what it was sent and fails on
 * demand. The backend reads memmap.c can call are weak stubs. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "config.h"
#include "upnpredirect.h"
#include "lease_table.h"
#include "memmap.h"
#include "fwsync.h"
#include "upnpglobalvars.h"

/* globals of the daemon which memmap.c uses */
const char * ext_if_name = "wan";
const char * ext_if_name6 = "wan";
unsigned int nextruletoclean_timestamp = 0;
int firewall_trust = FW_TRUST_CHECK;
static time_t now = 1000;

time_t upnp_time(void) { return now; }

const char *
proto_itoa(int proto)
{
	return proto == IPPROTO_TCP ? "TCP" : "UDP";
}

enum mapping_owner
mapping_owner_of(const char * desc, unsigned short eport, int proto)
{
	(void)eport; (void)proto;
	if(desc != NULL && strncmp(desc, "NAT-PMP ", 8) == 0)
		return MAPPING_NATPMP;
	return MAPPING_UPNP;
}

/* the backend reads of memmap.c, which the tests do not reach */
#define WEAK __attribute__((weak))
static int rule_present;	/* what get_redirect_rule() says */
WEAK int get_redirect_rule(const char * ifname, unsigned short eport, int proto,
                           char * iaddr, int iaddrlen, unsigned short * iport,
                           char * desc, int desclen, char * rhost, int rhostlen,
                           unsigned int * timestamp, u_int64_t * packets, u_int64_t * bytes)
{ (void)ifname; (void)eport; (void)proto; (void)iaddr; (void)iaddrlen; (void)iport;
  (void)desc; (void)desclen; (void)rhost; (void)rhostlen; (void)timestamp;
  (void)packets; (void)bytes; return rule_present ? 0 : -1; }
WEAK int get_redirect_rule_by_index(int index, char * ifname, unsigned short * eport,
                                    char * iaddr, int iaddrlen, unsigned short * iport,
                                    int * proto, char * desc, int desclen,
                                    char * rhost, int rhostlen, unsigned int * timestamp,
                                    u_int64_t * packets, u_int64_t * bytes)
{ (void)index; (void)ifname; (void)eport; (void)iaddr; (void)iaddrlen; (void)iport;
  (void)proto; (void)desc; (void)desclen; (void)rhost; (void)rhostlen; (void)timestamp;
  (void)packets; (void)bytes; return -1; }
#if defined(USE_NETFILTER) && !defined(USE_NFTABLES)
WEAK int get_redirect_rules_counters(void (*fn)(unsigned short eport, int proto,
                                                u_int64_t packets, u_int64_t bytes,
                                                void * arg),
                                     void * arg)
{ (void)fn; (void)arg; return -1; }
#endif
#ifdef FW_PINHOLES
WEAK int find_pinhole(const char * ifname, const char * rem_host, unsigned short rem_port,
                      const char * int_client, unsigned short int_port, int proto,
                      char * desc, int desc_len, unsigned int * timestamp)
{ (void)ifname; (void)rem_host; (void)rem_port; (void)int_client; (void)int_port;
  (void)proto; (void)desc; (void)desc_len; (void)timestamp; return -1; }
WEAK int get_pinhole_info(unsigned short uid, char * rem_host, int rem_hostlen,
                          unsigned short * rem_port, char * int_client, int int_clientlen,
                          unsigned short * int_port, int * proto, char * desc, int desclen,
                          unsigned int * timestamp, u_int64_t * packets, u_int64_t * bytes)
{ (void)uid; (void)rem_host; (void)rem_hostlen; (void)rem_port; (void)int_client;
  (void)int_clientlen; (void)int_port; (void)proto; (void)desc; (void)desclen;
  (void)timestamp; (void)packets; (void)bytes; return -1; }
WEAK int get_pinhole_uid_by_index(int index) { (void)index; return -1; }
WEAK int clean_pinhole_list(unsigned int * next_timestamp) { (void)next_timestamp; return 0; }
#endif
WEAK int get_peer_rule_by_index(int index, char * ifname, unsigned short * eport,
                                char * iaddr, int iaddrlen, unsigned short * iport,
                                int * proto, char * desc, int desclen,
                                char * rhost, int rhostlen, unsigned short * rport,
                                unsigned int * timestamp, u_int64_t * packets, u_int64_t * bytes)
{ (void)index; (void)ifname; (void)eport; (void)iaddr; (void)iaddrlen; (void)iport;
  (void)proto; (void)desc; (void)desclen; (void)rhost; (void)rhostlen; (void)rport;
  (void)timestamp; (void)packets; (void)bytes; return -1; }
WEAK int get_nat_ext_addr(struct sockaddr * src, struct sockaddr * dst, uint8_t proto,
                          struct sockaddr * ret_ext)
{ (void)src; (void)dst; (void)proto; (void)ret_ext; return -1; }

/* the fake firewall */
static int calls;		/* fw_sync() calls */
static int sent;		/* changes in the last call */
static int fail_at = -1;	/* the change which fails, -1 : none */
static enum fw_applied stays = FW_NOT_APPLIED;	/* what the changes before it are */
static enum fw_applied failed_as = FW_NOT_APPLIED;	/* what the failed change is */
static int uid_override;	/* the uid the backend gives the next pinhole */
static int next_uid = 1;	/* else the backend counts */
static struct fw_change last[8];
/* what the rows of the last call held: they can be freed after it */
static unsigned short last_old_iport, last_row_iport, last_old_eport;

int
fw_sync(struct fw_change * c, int n)
{
	int i;
	calls++;
	sent = n;
	for(i = 0; i < n; i++) {
		c[i].applied = FW_APPLIED;
		if(c[i].op == FW_ADD && c[i].row->family == AF_INET6)
			c[i].uid = (unsigned short)(uid_override ? uid_override : next_uid++);
	}
	if(n <= 8)
		memcpy(last, c, n * sizeof(*c));
	last_old_iport = c[0].old ? c[0].old->iport : 0;
	last_old_eport = c[0].old ? c[0].old->eport : 0;
	last_row_iport = c[0].row ? c[0].row->iport : 0;
	if(fail_at < 0 || fail_at >= n)
		return 0;
	for(i = 0; i < fail_at; i++)
		c[i].applied = stays;
	c[fail_at].applied = failed_as;
	for(i = fail_at + 1; i < n; i++)
		c[i].applied = FW_NOT_APPLIED;
	return -1;
}

static void
reset(void)
{
	lease_table_clear();
	calls = sent = 0;
	fail_at = -1;
	stays = failed_as = FW_NOT_APPLIED;
	uid_override = 0;
	nextruletoclean_timestamp = 0;
}

static void
map(struct memmap_change * c, enum memmap_op op, unsigned short eport,
    const char * iaddr, unsigned short iport, const char * desc, unsigned int ts)
{
	memset(c, 0, sizeof(*c));
	c->op = op;
	c->eport = eport;
	c->iaddr = iaddr;
	c->iport = iport;
	c->proto = IPPROTO_TCP;
	c->desc = desc;
	c->timestamp = ts;
}

static int
has_map(unsigned short eport, char * desc, unsigned int * ts)
{
	return memmap_get_map(eport, IPPROTO_TCP, NULL, NULL, 0, desc, desc ? 64 : 0,
	                      NULL, 0, ts) == 0;
}

static void
test_add(void)
{
	struct memmap_change c;
	reset();
	map(&c, MEMMAP_ADD, 1000, "192.168.1.10", 80, "web", 2000);
	assert(memmap_sync(&c, 1) == 0);
	assert(calls == 1 && sent == 1 && last[0].op == FW_ADD);
	assert(has_map(1000, NULL, NULL));
	assert(memmap_map_count() == 1);
}

static void
test_add_refused(void)
{
	struct memmap_change c;
	reset();
	fail_at = 0;
	map(&c, MEMMAP_ADD, 1000, "192.168.1.10", 80, "web", 2000);
	assert(memmap_sync(&c, 1) < 0);
	assert(!has_map(1000, NULL, NULL));
	assert(lease_table_count() == 0);
}

/* one call for the whole request, and nothing in the table after a failure */
static void
test_request_all_or_nothing(void)
{
	struct memmap_change c[3];
	reset();
	map(&c[0], MEMMAP_ADD, 1001, "192.168.1.10", 81, "a", 0);
	map(&c[1], MEMMAP_ADD, 1002, "192.168.1.10", 82, "b", 0);
	map(&c[2], MEMMAP_ADD, 1003, "192.168.1.10", 83, "c", 0);
	fail_at = 2;
	assert(memmap_sync(c, 3) < 0);
	assert(calls == 1 && sent == 3);
	assert(lease_table_count() == 0);
	fail_at = -1;
	assert(memmap_sync(c, 3) == 0);
	assert(calls == 2 && lease_table_count() == 3);
	assert(has_map(1001, NULL, NULL) && has_map(1002, NULL, NULL) &&
	       has_map(1003, NULL, NULL));
}

/* a change the firewall could not take back keeps its row */
static void
test_change_stays(void)
{
	struct memmap_change c[2];
	reset();
	map(&c[0], MEMMAP_ADD, 1001, "192.168.1.10", 81, "a", 0);
	map(&c[1], MEMMAP_ADD, 1002, "192.168.1.10", 82, "b", 0);
	fail_at = 1;
	stays = FW_APPLIED;
	assert(memmap_sync(c, 2) < 0);
	assert(has_map(1001, NULL, NULL));
	assert(!has_map(1002, NULL, NULL));
}

/* half added: the row is there, and expires now so the expiry retries */
static void
test_half_applied(void)
{
	struct memmap_change c;
	unsigned int ts;
	reset();
	fail_at = 0;
	failed_as = FW_HALF_APPLIED;
	map(&c, MEMMAP_ADD, 1000, "192.168.1.10", 80, "web", 5000);
	assert(memmap_sync(&c, 1) < 0);
	assert(has_map(1000, NULL, &ts));
	assert(ts == (unsigned int)now);
	assert(nextruletoclean_timestamp == (unsigned int)now);
}

/* an update of the same rule keeps the row and its place on the list */
static void
test_update_in_place(void)
{
	struct memmap_change c;
	char desc[64];
	unsigned int ts;
	unsigned short eport;
	int proto;
	reset();
	map(&c, MEMMAP_ADD, 1000, "192.168.1.10", 80, "first", 2000);
	assert(memmap_sync(&c, 1) == 0);
	map(&c, MEMMAP_ADD, 1001, "192.168.1.11", 80, "second", 2000);
	assert(memmap_sync(&c, 1) == 0);
	map(&c, MEMMAP_UPDATE, 1000, "192.168.1.10", 80, "renamed", 3000);
	assert(memmap_sync(&c, 1) == 0);
	assert(last[0].op == FW_UPDATE && last_old_iport == 80 && last_row_iport == 80);
	assert(has_map(1000, desc, &ts));
	assert(strcmp(desc, "renamed") == 0 && ts == 3000);
	assert(memmap_get_map_at(0, &eport, &proto, NULL, NULL, 0, NULL, 0, NULL, 0, NULL) == 0);
	assert(eport == 1000);
	assert(lease_table_count() == 2);
	/* a refused update leaves the row as it was */
	fail_at = 0;
	map(&c, MEMMAP_UPDATE, 1000, "192.168.1.10", 80, "refused", 4000);
	assert(memmap_sync(&c, 1) < 0);
	assert(has_map(1000, desc, &ts));
	assert(strcmp(desc, "renamed") == 0 && ts == 3000);
}

/* a renewal changes the table, and sends nothing to the firewall */
static void
test_renew_map(void)
{
	struct memmap_change c;
	char desc[64];
	unsigned int ts;
	reset();
	map(&c, MEMMAP_ADD, 1000, "192.168.1.10", 80, "web", 2000);
	assert(memmap_sync(&c, 1) == 0 && calls == 1);
	assert(memmap_renew_map(1000, IPPROTO_TCP, "web", 3000) == 0);
	assert(calls == 1);
	assert(has_map(1000, desc, &ts));
	assert(strcmp(desc, "web") == 0 && ts == 3000);
	/* the description of the client changes with it */
	assert(memmap_renew_map(1000, IPPROTO_TCP, "renamed", 4000) == 0);
	assert(has_map(1000, desc, &ts));
	assert(strcmp(desc, "renamed") == 0 && ts == 4000);
	assert(calls == 1 && lease_table_count() == 1);
	/* no row: nothing to renew */
	assert(memmap_renew_map(1001, IPPROTO_TCP, "web", 3000) < 0);
	assert(memmap_renew_map(1000, IPPROTO_UDP, "web", 3000) < 0);
	assert(calls == 1 && lease_table_count() == 1);
}

/* Before a renewal the protocols ask memmap_map_in_firewall(). A rule the
 * firewall lost is added again from its row, which stays. If the add fails,
 * the row goes, so the caller maps anew instead of renewing a closed port. */
static void
test_renew_lost_rule(void)
{
	struct memmap_change c;
	reset();
	rule_present = 1;
	map(&c, MEMMAP_ADD, 1000, "192.168.1.10", 80, "web", 2000);
	assert(memmap_sync(&c, 1) == 0 && calls == 1);
	assert(memmap_map_in_firewall(1000, IPPROTO_TCP) == 1);
	assert(lease_table_count() == 1);
	rule_present = 0;
	/* lost: a delete of what is left, and an add of the row's rule */
	assert(memmap_map_in_firewall(1000, IPPROTO_TCP) == 1);
	assert(calls == 3 && lease_table_count() == 1);
	assert(last[0].op == FW_ADD && last[0].row->eport == 1000 && last[0].row->iport == 80);
	assert(memmap_renew_map(1000, IPPROTO_TCP, "web", 3000) == 0);
	/* lost, and the add fails: the row goes */
	fail_at = 0;
	assert(memmap_map_in_firewall(1000, IPPROTO_TCP) == 0);
	assert(calls == 5 && lease_table_count() == 0);
	assert(memmap_renew_map(1000, IPPROTO_TCP, "web", 3000) < 0);
	fail_at = -1;
	/* trusted, the firewall is not asked: the row stays, and renews */
	firewall_trust = FW_TRUST_TRUST;
	map(&c, MEMMAP_ADD, 1000, "192.168.1.10", 80, "web", 2000);
	assert(memmap_sync(&c, 1) == 0 && calls == 6);
	assert(memmap_map_in_firewall(1000, IPPROTO_TCP) == 1);
	assert(memmap_renew_map(1000, IPPROTO_TCP, "web", 5000) == 0);
	assert(calls == 6 && lease_table_count() == 1);
	firewall_trust = FW_TRUST_CHECK;
}

/* a renewal with the description of another protocol gives the row to it, as
 * an add with that description does */
static void
test_renew_owner(void)
{
	struct memmap_change c;
	unsigned short eport = 0;
	char desc[64];
	reset();
	map(&c, MEMMAP_ADD, 1000, "192.168.1.10", 80, "NAT-PMP 1000 TCP", 2000);
	assert(memmap_sync(&c, 1) == 0);
	assert(memmap_renew_map(1000, IPPROTO_TCP, "upnp game", 3000) == 0);
	assert(has_map(1000, desc, NULL) && strcmp(desc, "upnp game") == 0);
	assert(memmap_find_map("192.168.1.10", 80, IPPROTO_TCP, MAPPING_UPNP, &eport,
	                       NULL, 0, NULL) == 0 && eport == 1000);
	assert(memmap_find_map("192.168.1.10", 80, IPPROTO_TCP, MAPPING_NATPMP, &eport,
	                       NULL, 0, NULL) < 0);
}

/* an update to another internal port replaces the row */
static void
test_update_new_port(void)
{
	struct memmap_change c;
	unsigned short iport;
	reset();
	map(&c, MEMMAP_ADD, 1000, "192.168.1.10", 80, "web", 2000);
	assert(memmap_sync(&c, 1) == 0);
	map(&c, MEMMAP_UPDATE, 1000, "192.168.1.10", 8080, "web", 2000);
	assert(memmap_sync(&c, 1) == 0);
	assert(last_old_iport == 80 && last_row_iport == 8080);
	assert(memmap_get_map(1000, IPPROTO_TCP, &iport, NULL, 0, NULL, 0, NULL, 0, NULL) == 0);
	assert(iport == 8080 && lease_table_count() == 1);
}

static void
test_delete(void)
{
	struct memmap_change c;
	reset();
	map(&c, MEMMAP_ADD, 1000, "192.168.1.10", 80, "web", 2000);
	assert(memmap_sync(&c, 1) == 0);
	fail_at = 0;
	map(&c, MEMMAP_DELETE, 1000, NULL, 0, NULL, 0);
	assert(memmap_sync(&c, 1) < 0);
	assert(has_map(1000, NULL, NULL));
	fail_at = -1;
	assert(memmap_sync(&c, 1) == 0);
	assert(last[0].op == FW_DELETE && last_old_eport == 1000);
	assert(!has_map(1000, NULL, NULL) && lease_table_count() == 0);
	/* a rule with no row is still deleted in the firewall */
	assert(memmap_sync(&c, 1) == 0);
	assert(last[0].op == FW_DELETE && last_old_eport == 1000);
}

static void
pinhole(struct memmap_change * c, enum memmap_op op, int uid, const char * iaddr,
        unsigned short iport, unsigned int ts)
{
	memset(c, 0, sizeof(*c));
	c->op = op;
	c->uid = uid;
	c->iaddr = iaddr;
	c->iport = iport;
	c->eport = iport;
	c->proto = IPPROTO_UDP;
	c->desc = "pinhole";
	c->timestamp = ts;
}

/* the backend gives the uid, and a failed add leaves no row */
static void
test_pinhole_uid(void)
{
	struct memmap_change c;
	int uid;
	reset();
	pinhole(&c, MEMMAP_ADD, 0, "2001:db8::10", 5000, 2000);
	assert(memmap_sync(&c, 1) == 0);
	uid = c.uid;
	assert(uid > 0 && last[0].uid == uid);
	assert(lease_table_find_uid((unsigned short)uid) != NULL);
	fail_at = 0;
	pinhole(&c, MEMMAP_ADD, 0, "2001:db8::11", 5001, 2000);
	assert(memmap_sync(&c, 1) < 0);
	assert(lease_table_find_uid((unsigned short)c.uid) == NULL);
	fail_at = -1;
	/* renew by uid only: the row gets the new expiry */
	pinhole(&c, MEMMAP_RENEW, uid, NULL, 0, 3000);
	assert(memmap_sync(&c, 1) == 0);
	assert(last[0].op == FW_UPDATE && last[0].uid == uid);
	assert(lease_table_find_uid((unsigned short)uid)->expiry == 3000);
	pinhole(&c, MEMMAP_DELETE_PINHOLE, uid, NULL, 0, 0);
	assert(memmap_sync(&c, 1) == 0);
	assert(lease_table_find_uid((unsigned short)uid) == NULL);
	assert(lease_table_count() == 0);
}

/* the row takes the uid the backend gave */
static void
test_pinhole_backend_uid(void)
{
	struct memmap_change c;
	reset();
	uid_override = 777;
	pinhole(&c, MEMMAP_ADD, 0, "2001:db8::10", 5000, 2000);
	assert(memmap_sync(&c, 1) == 0);
	assert(c.uid == 777);
	assert(lease_table_find_uid(777) != NULL);
}

/* a request whose row cannot be built sends nothing */
static void
test_bad_address(void)
{
	struct memmap_change c;
	reset();
	map(&c, MEMMAP_ADD, 1000, "not an address", 80, "web", 2000);
	assert(memmap_sync(&c, 1) < 0);
	assert(calls == 0 && lease_table_count() == 0);
}

/* two changes of one request to one row are refused, and nothing is sent */
static void
test_one_row_twice(void)
{
	struct memmap_change c[2];
	char desc[64];
	reset();
	map(&c[0], MEMMAP_ADD, 1000, "192.168.1.10", 80, "a", 2000);
	assert(memmap_sync(&c[0], 1) == 0 && calls == 1);
	map(&c[0], MEMMAP_DELETE, 1000, NULL, 0, NULL, 0);
	map(&c[1], MEMMAP_ADD, 1000, "192.168.1.11", 81, "b", 2000);
	assert(memmap_sync(c, 2) < 0);
	assert(calls == 1);
	assert(has_map(1000, desc, NULL) && strcmp(desc, "a") == 0);
	assert(memmap_map_count() == 1);
	/* two adds of one new port: neither goes */
	map(&c[0], MEMMAP_ADD, 1001, "192.168.1.10", 81, "c", 2000);
	map(&c[1], MEMMAP_ADD, 1001, "192.168.1.11", 82, "d", 2000);
	assert(memmap_sync(c, 2) < 0);
	assert(calls == 1 && memmap_map_count() == 1);
}

int
main(void)
{
	openlog("testmemmapsync", LOG_PERROR, LOG_USER);
	setlogmask(LOG_UPTO(LOG_WARNING));
	test_add();
	test_add_refused();
	test_request_all_or_nothing();
	test_change_stays();
	test_half_applied();
	test_update_in_place();
	test_renew_map();
	test_renew_lost_rule();
	test_renew_owner();
	test_update_new_port();
	test_delete();
	test_pinhole_uid();
	test_pinhole_backend_uid();
	test_bad_address();
	test_one_row_twice();
	lease_table_clear();
	printf("testmemmapsync: all tests passed\n");
	return 0;
}
