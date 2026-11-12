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
static int rule_present;	/* 1: get_redirect_rule() finds the rule, 0: not, -1: an error */
static int pinhole_gone;	/* get_pinhole_packets() finds no rule */
WEAK int get_redirect_rule(const char * ifname, unsigned short eport, int proto,
                           char * iaddr, int iaddrlen, unsigned short * iport,
                           char * desc, int desclen, char * rhost, int rhostlen,
                           unsigned int * timestamp, u_int64_t * packets, u_int64_t * bytes)
{ (void)ifname; (void)eport; (void)proto; (void)iaddr; (void)iaddrlen; (void)iport;
  (void)desc; (void)desclen; (void)rhost; (void)rhostlen; (void)timestamp;
  (void)packets; (void)bytes; return rule_present > 0 ? 0 : rule_present == 0 ? -2 : -1; }
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
/* the port forwards of other programs, for memmap_eport_redirected_elsewhere() */
WEAK int get_nat_redirect_rule(const char * nat_chain_name, const char * ifname,
                               unsigned short eport, int proto,
                               char * iaddr, int iaddrlen, unsigned short * iport,
                               char * desc, int desclen, char * rhost, int rhostlen,
                               unsigned int * timestamp, u_int64_t * packets, u_int64_t * bytes)
{ (void)nat_chain_name; (void)ifname; (void)eport; (void)proto; (void)iaddr; (void)iaddrlen;
  (void)iport; (void)desc; (void)desclen; (void)rhost; (void)rhostlen; (void)timestamp;
  (void)packets; (void)bytes; return -1; }
#endif
#ifdef FW_PINHOLES
WEAK int get_pinhole_packets(const char * rem_host, unsigned short rem_port,
                             const char * int_client, unsigned short int_port,
                             int proto, u_int64_t * packets)
{ (void)rem_host; (void)rem_port; (void)int_client; (void)int_port; (void)proto;
  (void)packets; return pinhole_gone ? -2 : 0; }
WEAK int get_pinhole_rule_at(int index, char * rem_host, int rem_hostlen,
                             unsigned short * rem_port, char * int_client, int int_clientlen,
                             unsigned short * int_port, int * proto, char * desc, int desclen)
{ (void)index; (void)rem_host; (void)rem_hostlen; (void)rem_port; (void)int_client;
  (void)int_clientlen; (void)int_port; (void)proto; (void)desc; (void)desclen; return -1; }
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

/* the fake firewall */
static int calls;		/* fw_sync() calls */
static int sent;		/* changes in the last call */
static int fail_at = -1;	/* the change which fails, -1 : none */
static int fail_call;		/* only in this call (1 the first), 0 : in each */
static enum fw_applied stays = FW_NOT_APPLIED;	/* what the changes before it are */
static enum fw_applied failed_as = FW_NOT_APPLIED;	/* what the failed change is */
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
	}
	if(n <= 8)
		memcpy(last, c, n * sizeof(*c));
	last_old_iport = c[0].old ? c[0].old->iport : 0;
	last_old_eport = c[0].old ? c[0].old->eport : 0;
	last_row_iport = c[0].row ? c[0].row->iport : 0;
	if(fail_at < 0 || fail_at >= n || (fail_call != 0 && calls != fail_call))
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
	fail_call = 0;
	stays = failed_as = FW_NOT_APPLIED;
	nextruletoclean_timestamp = 0;
}

static void
map(struct memmap_change * c, enum memmap_op op, unsigned short eport,
    const char * iaddr, unsigned short iport, const char * desc, unsigned int ts)
{
	memmap_change_init(c, op, 0, NULL, 0, eport, iaddr, iport, IPPROTO_TCP, desc, ts);
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

/* a request of more changes than memmap_sync() stages on the stack is all or
 * nothing too */
static void
test_large_request(void)
{
	struct memmap_change c[7];
	char desc[7][8];
	int i;
	reset();
	for(i = 0; i < 7; i++) {
		snprintf(desc[i], sizeof(desc[i]), "m%d", i);
		map(&c[i], MEMMAP_ADD, (unsigned short)(1001 + i), "192.168.1.10",
		    (unsigned short)(81 + i), desc[i], 0);
	}
	fail_at = 5;
	assert(memmap_sync(c, 7) < 0);
	assert(calls == 1 && sent == 7 && lease_table_count() == 0);
	fail_at = -1;
	assert(memmap_sync(c, 7) == 0);
	assert(calls == 2 && lease_table_count() == 7);
	for(i = 0; i < 7; i++)
		assert(has_map((unsigned short)(1001 + i), NULL, NULL));
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
	/* the client tries again before the expiry: the redirect rule is
	 * there, but the row is not renewed as it is. Its rules go and come
	 * again, with no check of the firewall, trusted or not */
	fail_at = -1;
	rule_present = 1;
	firewall_trust = FW_TRUST_TRUST;
	assert(memmap_map_in_firewall(1000, IPPROTO_TCP) == 1);
	assert(calls == 3 && last[0].op == FW_ADD);
	assert(!lease_table_find_mapping(IPPROTO_TCP, AF_INET, NULL, 1000)->fw_partial);
	/* whole again: a renewal checks no more */
	assert(memmap_map_in_firewall(1000, IPPROTO_TCP) == 1 && calls == 3);
	firewall_trust = FW_TRUST_CHECK;
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
static void test_renew_lost_rule_half(void);

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
	/* a firewall which cannot be read: the rule is not added again */
	rule_present = -1;
	assert(memmap_map_in_firewall(1000, IPPROTO_TCP) == 1);
	assert(calls == 1 && lease_table_count() == 1);
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

/* A lost rule whose add leaves the redirect rule without its filter rule: the
 * part which stayed is deleted at once, and the row goes. If that delete
 * fails too, the row stays and expires at once, so the expiry tries again:
 * without the row nothing would delete the rule. */
static void
test_renew_lost_rule_half(void)
{
	struct memmap_change c;
	reset();
	rule_present = 1;
	map(&c, MEMMAP_ADD, 1000, "192.168.1.10", 80, "web", 2000);
	assert(memmap_sync(&c, 1) == 0 && calls == 1);
	rule_present = 0;
	/* the delete of what is left, the half add, the delete which works */
	fail_at = 0;
	failed_as = FW_HALF_APPLIED;
	fail_call = 3;
	assert(memmap_map_in_firewall(1000, IPPROTO_TCP) == 0);
	assert(calls == 4 && last[0].op == FW_DELETE && lease_table_count() == 0);

	reset();
	rule_present = 1;
	map(&c, MEMMAP_ADD, 1000, "192.168.1.10", 80, "web", 2000);
	assert(memmap_sync(&c, 1) == 0);
	rule_present = 0;
	/* each call fails half: the row stays, and expires now */
	fail_at = 0;
	failed_as = FW_HALF_APPLIED;
	assert(memmap_map_in_firewall(1000, IPPROTO_TCP) == 0);
	assert(calls == 4 && lease_table_count() == 1);
	assert(lease_table_find_mapping(IPPROTO_TCP, AF_INET, NULL, 1000)->expiry == (time_t)now);
	assert(nextruletoclean_timestamp == (unsigned int)now);
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
	memmap_change_init(c, op, uid, NULL, 0, iport, iaddr, iport, IPPROTO_UDP, "pinhole", ts);
	c->give_uid = 1;	/* UPnP; a PCP pinhole has none */
}

/* the map gives the uid, and takes it back when the add fails */
static void
test_pinhole_uid(void)
{
	struct memmap_change c;
	int uid;
	reset();
	pinhole(&c, MEMMAP_ADD, 0, "2001:db8::10", 5000, 2000);
	assert(memmap_sync(&c, 1) == 0);
	uid = c.uid;
	assert(uid > 0);
	assert(lease_table_find_uid((unsigned short)uid) != NULL);
	fail_at = 0;
	pinhole(&c, MEMMAP_ADD, 0, "2001:db8::11", 5001, 2000);
	assert(memmap_sync(&c, 1) < 0);
	assert(lease_table_find_uid((unsigned short)c.uid) == NULL);
	fail_at = -1;
	/* a renewal changes the row, and sends nothing to the firewall */
	calls = 0;
	assert(memmap_renew_pinhole((unsigned short)uid, NULL, 3000) == 0);
	assert(calls == 0);
	assert(lease_table_find_uid((unsigned short)uid)->expiry == 3000);
	assert(memmap_renew_pinhole((unsigned short)uid, "renamed", 4000) == 0);
	assert(lease_table_find_uid((unsigned short)uid)->expiry == 4000);
	assert(strcmp(lease_table_find_uid((unsigned short)uid)->label, "renamed") == 0);
	assert(memmap_renew_pinhole((unsigned short)(uid + 1), NULL, 3000) == -1);
	assert(calls == 0);
	/* the firewall lost the rule: what is left goes, and the row is added */
	pinhole_gone = 1;
	assert(memmap_renew_pinhole((unsigned short)uid, NULL, 5000) == 0);
	assert(calls == 2 && last[0].op == FW_ADD && last[0].row->iport == 5000);
	assert(lease_table_find_uid((unsigned short)uid)->expiry == 5000);
	/* the add fails: the renewal fails, the row stays as it was */
	fail_at = 0;
	assert(memmap_renew_pinhole((unsigned short)uid, NULL, 6000) == -3);
	fail_at = -1;
	assert(lease_table_find_uid((unsigned short)uid)->expiry == 5000);
	/* trusted, the firewall is not asked */
	firewall_trust = FW_TRUST_TRUST;
	calls = 0;
	assert(memmap_renew_pinhole((unsigned short)uid, NULL, 7000) == 0);
	assert(calls == 0 && lease_table_find_uid((unsigned short)uid)->expiry == 7000);
	firewall_trust = FW_TRUST_CHECK;
	pinhole_gone = 0;
	pinhole(&c, MEMMAP_DELETE_PINHOLE, uid, NULL, 0, 0);
	assert(memmap_sync(&c, 1) == 0);
	assert(lease_table_find_uid((unsigned short)uid) == NULL);
	assert(lease_table_count() == 0);
}

/* a pinhole is read from the table; the firewall finds its rule by key */
static void
test_pinhole_key(void)
{
	struct memmap_change c;
	char iaddr[64], desc[64];
	unsigned short iport;
	unsigned int ts;
	int uid, calls_before;
	reset();
	pinhole(&c, MEMMAP_ADD, 0, "2001:db8::20", 6000, 2000);
	assert(memmap_sync(&c, 1) == 0);
	uid = memmap_find_pinhole(NULL, 0, "2001:db8::20", 6000, IPPROTO_UDP,
	                          desc, sizeof(desc), &ts);
	assert(uid == c.uid && strcmp(desc, "pinhole") == 0 && ts == 2000);
	assert(memmap_find_pinhole(NULL, 0, "2001:db8::21", 6000, IPPROTO_UDP,
	                           NULL, 0, NULL) == -2);
	assert(memmap_get_pinhole((unsigned short)uid, NULL, 0, NULL, iaddr, sizeof(iaddr),
	                          &iport, NULL, NULL, 0, NULL, NULL) == 0);
	assert(strcmp(iaddr, "2001:db8::20") == 0 && iport == 6000);
	assert(memmap_pinhole_uid_at(0) == uid && memmap_pinhole_uid_at(1) == -1);
	/* a delete with neither row nor key sends nothing */
	calls_before = calls;
	pinhole(&c, MEMMAP_DELETE_PINHOLE, 999, NULL, 0, 0);
	assert(memmap_sync(&c, 1) == -2 && calls == calls_before);
	/* a delete with no row but a key goes to the firewall, by the key */
	pinhole(&c, MEMMAP_DELETE_PINHOLE, 999, "2001:db8::30", 7000, 0);
	assert(memmap_sync(&c, 1) == 0 && calls == calls_before + 1);
	assert(last[0].op == FW_DELETE && last_old_iport == 7000);
	assert(lease_table_count() == 1);
}

/* a PCP pinhole has no uid: it is renewed, expired and deleted by its rule.
 * A UPnP client which takes it over gets a uid. */
static void
test_pcp_pinhole(void)
{
	struct memmap_change c;
	struct expired_pinhole expired[2];
	unsigned int next;
	const struct lease_entry * row;
	unsigned short u;
	int r;
	reset();
	pinhole(&c, MEMMAP_ADD, 0, "2001:db8::40", 8000, 500);
	c.give_uid = 0;
	assert(memmap_sync(&c, 1) == 0 && c.uid == 0);
	assert(memmap_find_pinhole(NULL, 0, "2001:db8::40", 8000, IPPROTO_UDP,
	                           NULL, 0, NULL) == 0);
	assert(memmap_pinhole_uid_at(0) == -1);	/* no uid to list */
	/* PCP rows leave the uids to UPnP */
	u = lease_table_new_uid();
	assert(u != 0 && lease_table_find_uid(u) == NULL);
	/* a renewal by its rule */
	calls = 0;
	assert(memmap_renew_pinhole_at(NULL, 0, "2001:db8::40", 8000, IPPROTO_UDP,
	                               "pcp", 600, 0) == 0);
	assert(calls == 0);
	assert(memmap_renew_pinhole_at(NULL, 0, "2001:db8::41", 8000, IPPROTO_UDP,
	                               NULL, 600, 0) == -1);
	/* the expiry pass deletes it by its rule */
	assert(memmap_expired_pinholes((unsigned int)now, expired, 2, &next) == 1);
	assert(expired[0].uid == 0 && expired[0].iport == 8000);
	pinhole(&c, MEMMAP_DELETE_PINHOLE, 0, expired[0].iaddr, expired[0].iport, 0);
	assert(memmap_sync(&c, 1) == 0 && lease_table_count() == 0);
	/* a UPnP client takes over a PCP pinhole: a uid, in place */
	pinhole(&c, MEMMAP_ADD, 0, "2001:db8::42", 8001, 2000);
	c.give_uid = 0;
	assert(memmap_sync(&c, 1) == 0 && c.uid == 0);
	calls = 0;
	r = memmap_renew_pinhole_at(NULL, 0, "2001:db8::42", 8001, IPPROTO_UDP,
	                            "IGD2 pinhole", 3000, 1);
	assert(r > 0 && calls == 0 && lease_table_count() == 1);
	row = lease_table_find_uid((unsigned short)r);
	assert(row != NULL && row->expiry == 3000 && row->iport == 8001);
	assert(memmap_pinhole_uid_at(0) == r);
	/* renewed again, it keeps its uid */
	assert(memmap_renew_pinhole_at(NULL, 0, "2001:db8::42", 8001, IPPROTO_UDP,
	                               NULL, 4000, 1) == r);
	pinhole(&c, MEMMAP_DELETE_PINHOLE, r, NULL, 0, 0);
	assert(memmap_sync(&c, 1) == 0 && lease_table_count() == 0);
	assert(lease_table_find_uid((unsigned short)r) == NULL);
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

/* the expiry pass finds the expired pinholes in the table, with their rules,
 * and the next expiry; a full array makes the next pass run now */
static void
test_pinhole_expiry(void)
{
	struct memmap_change c;
	struct expired_pinhole expired[2];
	unsigned int next;
	char iaddr[3][32];
	int i, n;
	reset();
	for(i = 0; i < 3; i++) {
		snprintf(iaddr[i], sizeof(iaddr[i]), "2001:db8::%d", 20 + i);
		/* two expired (500, 600), one later (3000) */
		pinhole(&c, MEMMAP_ADD, 0, iaddr[i], (unsigned short)(6000 + i),
		        i < 2 ? (unsigned int)(500 + 100 * i) : 3000);
		assert(memmap_sync(&c, 1) == 0);
	}
	n = memmap_expired_pinholes((unsigned int)now, expired, 2, &next);
	assert(n == 2 && next == 3000);
	assert(expired[0].uid != 0 && expired[1].uid != 0);
	assert(expired[0].iport >= 6000 && expired[0].iport <= 6001);
	assert(expired[0].raddr[0] == '\0');
	n = memmap_expired_pinholes((unsigned int)now, expired, 1, &next);
	assert(n == 1 && next == (unsigned int)now);
	/* a delete of the expired ones, as the pass sends it */
	for(i = 0; i < 2; i++) {
		pinhole(&c, MEMMAP_DELETE_PINHOLE, expired[0].uid, NULL, 0, 0);
		n = memmap_expired_pinholes((unsigned int)now, expired, 2, &next);
		assert(n == 2 - i);
		pinhole(&c, MEMMAP_DELETE_PINHOLE, expired[0].uid, expired[0].iaddr,
		        expired[0].iport, 0);
		assert(memmap_sync(&c, 1) == 0);
	}
	n = memmap_expired_pinholes((unsigned int)now, expired, 2, &next);
	assert(n == 0 && next == 3000);
	assert(lease_table_count() == 1);
}

int
main(void)
{
	openlog("testmemmapsync", LOG_PERROR, LOG_USER);
	setlogmask(LOG_UPTO(LOG_WARNING));
	test_add();
	test_add_refused();
	test_request_all_or_nothing();
	test_large_request();
	test_change_stays();
	test_half_applied();
	test_update_in_place();
	test_renew_map();
	test_renew_lost_rule();
	test_renew_lost_rule_half();
	test_renew_owner();
	test_update_new_port();
	test_delete();
	test_pinhole_uid();
	test_pinhole_key();
	test_pcp_pinhole();
	test_bad_address();
	test_one_row_twice();
	test_pinhole_expiry();
	lease_table_clear();
	printf("testmemmapsync: all tests passed\n");
	return 0;
}
