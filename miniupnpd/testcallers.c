/* MiniUPnP project
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

/* Unit test of the callers of fw_sync(): what upnpredirect.c and
 * upnppinhole.c record in the table when the firewall fails them. The
 * real redirect, pinhole, memmap, table and NAT-PMP code, on the fake
 * firewall of testfwfake.c. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#include "config.h"
#include "upnpglobalvars.h"
#include "upnputils.h"
#include "upnpredirect.h"
#include "memmap.h"
#include "fwsync.h"
#include "testfwfake.h"
#ifdef ENABLE_EVENTS
#include "upnpevents.h"
#endif
#ifdef ENABLE_UPNPPINHOLE
#include "upnppinhole.h"
#endif
#ifdef CHECK_PORTINUSE
#include "portinuse.h"
#endif
#ifdef ENABLE_NATPMP
#include "natpmp.h"
#endif

static int failures;

#define CHECK(cond) do { if(!(cond)) { \
	fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #cond); \
	failures++; } } while(0)

/* the parts of the daemon these tests do not reach */
#ifdef ENABLE_EVENTS
void
upnp_event_var_change_notify(enum subscriber_service_enum service)
{
	(void)service;
}
#endif
#ifdef CHECK_PORTINUSE
int
port_in_use(const char * if_name, unsigned port, int proto, const char * iaddr,
            unsigned iport)
{
	(void)if_name; (void)port; (void)proto; (void)iaddr; (void)iport;
	return 0;
}
#endif
int
get_src_for_route_to(const struct sockaddr * dst, void * src, size_t * src_len,
                     int * index)
{
	(void)dst; (void)src; (void)src_len; (void)index;
	return -1;
}

static const struct in6_addr any = IN6ADDR_ANY_INIT;

/* a row for the IPv4 port mapping 192.168.1.10:iport <- eport of kind */
static struct lease_entry *
map4(int kind, unsigned short eport, unsigned short iport)
{
	struct lease_entry * e = lease_table_new(0);
	int family;

	lease_entry_set_kind(e, kind, NULL);
	map_pton("192.168.1.10", &family, &e->iaddr);
	e->family = AF_INET;
	e->proto = IPPROTO_TCP;
	e->eport = eport;
	e->iport = iport;
	e->timestamp = (unsigned int)upnp_time() + 3600;
	e->label = "test";
	return e;
}

static struct lease_entry *
find4(unsigned short eport)
{
	return memmap_find_map(IPPROTO_TCP, AF_INET, &any, eport);
}

/* The filter rule of an add fails, and so does the delete of its redirect
 * rule: the add fails, and a row of the rule which stays expires at once. */
static void
test_add_half(void)
{
	struct lease_entry * row;
	struct lease_entry * e;

	lease_table_clear();	/* before a row: it frees the indexes */
	row = map4(MAP_KIND_UPNP, 5000, 5000);
	reset();
	fail_add_filter = 1;
	fail_delete = 1;
	CHECK(upnp_redirect_internal(row) < 0);
	lease_table_free(row);	/* the caller's, on failure */
	e = find4(5000);
	CHECK(e != NULL && e->fw_partial);
	CHECK(e != NULL && e->timestamp <= (unsigned int)upnp_time());
}

/* An expired mapping whose delete fails keeps its row, and is not tried
 * again before its retry is due. */
static void
test_expiry_retry(void)
{
	struct lease_entry * row;
	struct lease_entry * e;
	unsigned int now = (unsigned int)upnp_time();

	lease_table_clear();
	row = map4(MAP_KIND_UPNP, 5000, 5000);
	reset();
	row->timestamp = now - 1;
	CHECK(upnp_redirect_internal(row) == 0);
	fail_delete = 1;	/* the rule is there, its delete fails */
	expire_mappings();
	e = find4(5000);
	CHECK(e != NULL && e->retry > now);
	fail_delete = 0;
	expire_mappings();	/* the retry is not due yet */
	CHECK(find4(5000) != NULL && deletes == 0);
	if(e != NULL)
		e->retry = now - 1;	/* a minute later */
	expire_mappings();
	CHECK(find4(5000) == NULL && deletes == 1);
}

/* A renewal finds the rule of its row gone: it comes back, and the row
 * stays. Pointed elsewhere, it is replaced. If it cannot come back, the
 * row goes. */
static void
test_check_map(void)
{
	struct lease_entry * row;

	lease_table_clear();
	row = map4(MAP_KIND_UPNP, 5000, 5000);
	reset();
	CHECK(upnp_redirect_internal(row) == 0);

	reset();
	rule_present = 0;
	CHECK(upnp_check_map(row) == row && adds == 1);

	reset();
	rule_iaddr = "192.168.1.99";
	CHECK(upnp_check_map(row) == row && deletes == 1 && adds == 1);

	reset();
	rule_present = 0;
	fail_add_redirect = 1;
	CHECK(upnp_check_map(row) == NULL);
	CHECK(find4(5000) == NULL);
}

/* A row of a part of its rules: a renewal sends them all again, also in
 * a trusted firewall. If that fails, the row stays, expiring now, and is
 * not renewed in the table. */
static void
test_partial(void)
{
	struct lease_entry * row;
	struct lease_entry * e;
	struct lease_entry * req;

	lease_table_clear();
	row = map4(MAP_KIND_UPNP, 5000, 5000);
	reset();
	fail_add_filter = 1;
	fail_delete = 1;
	CHECK(upnp_redirect_internal(row) < 0);
	lease_table_free(row);
	e = find4(5000);
	CHECK(e != NULL && e->fw_partial);
	if(e == NULL)
		return;

	reset();
	firewall_trust = FW_TRUST_TRUST;
	CHECK(upnp_check_map(e) == e && !e->fw_partial && adds == 1);
	firewall_trust = FW_TRUST_CHECK;

	/* half again, and the resend fails: the row stays, no renewal */
	e->fw_partial = 1;
	reset();
	fail_add_filter = 1;
	fail_delete = 1;
	CHECK(upnp_check_map(e) == e && e->fw_partial);
	CHECK(e->timestamp <= (unsigned int)upnp_time());
	req = map4(MAP_KIND_UPNP, 5000, 5000);
	CHECK(upnp_renew_map(req, e) < 0);
	lease_table_free(req);
}

/* Only the protocol which made a mapping changes it */
static void
test_kind(void)
{
	struct lease_entry * pcp;
	struct lease_entry * req;
	struct lease_entry * e;

	lease_table_clear();
	pcp = map4(MAP_KIND_PCP, 5000, 5000);
	reset();
	CHECK(upnp_redirect_internal(pcp) == 0);
	req = map4(MAP_KIND_UPNP, 5000, 5000);
	CHECK(upnp_redirect(req) == -4);
	lease_table_free(req);
	e = find4(5000);
	CHECK(e != NULL && e->kind == MAP_KIND_PCP);

	/* UPnP renews its own */
	lease_table_clear();
	req = map4(MAP_KIND_UPNP, 5001, 5001);
	CHECK(upnp_redirect_internal(req) == 0);
	req = map4(MAP_KIND_UPNP, 5001, 5001);
	CHECK(upnp_redirect(req) == 0);	/* the table took req */
	CHECK(find4(5001) == req);
}

#if defined(PCP_PEER) && defined(USE_NETFILTER)
/* Two expired peers of a PEER binding, whose deletes fail: each keeps its
 * own retry, so one which fails does not hold up the others. */
static void
test_peer_retry(void)
{
	struct outgoing_entry * b = outgoing_table_new(2);
	unsigned int now = (unsigned int)upnp_time();
	int family;

	outgoing_table_clear();
	b->family = AF_INET;
	b->proto = IPPROTO_UDP;
	map_pton("192.168.1.10", &family, &b->iaddr);
	map_pton("203.0.113.1", &family, &b->eaddr);
	b->iport = 5000;
	b->eport = 6000;
	map_pton("198.51.100.7", &family, &b->peers[0].raddr);
	b->peers[0].rport = 7000;
	b->peers[0].timestamp = now - 1;
	b->peers[1] = b->peers[0];
	b->peers[1].rport = 7001;
	memmap_link_outgoing(b);

	reset();
	fail_delete = 1;	/* the rules are there, their deletes fail */
	expire_mappings();
	CHECK(b->npeers == 2);
	CHECK(b->peers[0].retry > now && b->peers[1].retry > now);

	/* the retry of the first is due: it goes, the second waits */
	reset();
	b->peers[0].retry = now - 1;
	expire_mappings();
	CHECK(deletes == 1 && b->npeers == 1 && b->peers[0].rport == 7001);
	outgoing_table_clear();
}
#endif

#ifdef FW_MAP6
/* a row for the IPv6 map [2001:db8::10]:5000 from [2001:db8:7::1]:6000 */
static struct lease_entry *
map6(int kind)
{
	struct lease_entry * e = lease_table_new(1);
	int family;

	lease_entry_set_kind(e, kind, NULL);
	e->family = AF_INET6;
	e->proto = IPPROTO_UDP;
	map_pton("2001:db8::10", &family, &e->iaddr);
	e->eaddr = e->iaddr;
	e->iport = e->eport = 5000;
	map_pton("2001:db8:7::1", &family, &e->filters[0].raddr);
	e->filters[0].prefix = 128;
	e->filters[0].rport = 6000;
	e->timestamp = (unsigned int)upnp_time() + 3600;
	return e;
}

static void
test_map6(void)
{
	struct lease_entry * req;
	struct lease_entry upd;
	struct map_filter f;
	unsigned short uid = 0;

	lease_table_clear();
	req = map6(MAP_KIND_UPNP);
	reset();
	CHECK(upnp_add_inboundpinhole(req, &uid) == 1 && uid != 0 && map6_adds == 1);

	/* UpdatePinhole names it by its UniqueID alone: its lost rule comes
	 * back */
	lease_entry_init(&upd, MAP_KIND_UPNP, NULL);
	upd.family = AF_INET6;
	upd.proto = IPPROTO_UDP;
	upd.iaddr = upd.eaddr = req->iaddr;
	upd.iport = upd.eport = 5000;
	memset(&f, 0, sizeof(f));
	f.uid = uid;
	upd.filters = &f;
	upd.nfilters = 1;
	upd.timestamp = (unsigned int)upnp_time() + 7200;
	reset();
	map6_lost = 1;
	CHECK(upnp_update_inboundpinhole(&upd, uid) == 0 && map6_adds == 1);

	/* another external port, with PREFER_FAILURE: refused, the map stays */
	req = map6(MAP_KIND_PCP);
	req->flags |= MAP_PREFER_FAILURE;
	req->eport = 5001;
	reset();
	CHECK(upnp_add_inboundpinhole(req, NULL) == -3 && map6_adds == 0);
	lease_table_free(req);

	/* the UPnP map, asked for by PCP: refused */
	req = map6(MAP_KIND_PCP);
	CHECK(upnp_add_inboundpinhole(req, NULL) == -4);
	lease_table_free(req);

	/* a PCP filter of another remote may not join the UPnP map */
	req = map6(MAP_KIND_PCP);
	req->filters[0].rport = 6001;
	CHECK(upnp_add_inboundpinhole(req, NULL) == -4);
	lease_table_free(req);
	CHECK(lease_table_count() == 1);
}

/* max_filters_per_map=0: a map of any remote is taken, one with a remote
 * host is refused, for UPnP and PCP alike */
static void
test_max_filters(void)
{
	struct lease_entry * req;
	int kinds[2] = { MAP_KIND_UPNP, MAP_KIND_PCP };
	int k;

	max_filters_per_map = 0;
	for(k = 0; k < 2; k++) {
		lease_table_clear();
		reset();
		req = map6(kinds[k]);
		CHECK(upnp_add_inboundpinhole(req, NULL) == -1 && map6_adds == 0);
		lease_table_free(req);

		req = map6(kinds[k]);
		memset(&req->filters[0].raddr, 0, sizeof(req->filters[0].raddr));
		req->filters[0].prefix = 0;
		req->filters[0].rport = 0;
		CHECK(upnp_add_inboundpinhole(req, NULL) == 1 && map6_adds == 1);
	}
	max_filters_per_map = -1;
	lease_table_clear();
}

#ifdef ENABLE_LEASEFILE
/* Two lease_file6 lines of one UniqueID, whose rules outlived the daemon:
 * the second line gets a new UniqueID, so its client can reach it. */
static void
test_reload_uid(void)
{
	const char * path = "testcallers.leases6";
	FILE * f;
	unsigned long ts = (unsigned long)time(NULL) + 3600;
	struct lease_entry * e;
	int family;
	struct in6_addr iaddr;

	lease_table_clear();
	f = fopen(path, "w");
	CHECK(f != NULL);
	if(f == NULL)
		return;
	fprintf(f, "UDP;2001:db8::10;5000;2001:db8:7::1;6000;7;%lu;test\n", ts);
	fprintf(f, "UDP;2001:db8::10;5000;2001:db8:7::1;6001;7;%lu;test\n", ts);
	fclose(f);
	lease_file6 = path;
	reset();
	CHECK(reload_from_lease_file6() == 0);
	lease_file6 = NULL;
	remove(path);
	CHECK(map6_adds == 0);	/* the rules were there */

	map_pton("2001:db8::10", &family, &iaddr);
	e = lease_table_find_entry(IPPROTO_UDP, AF_INET6, &iaddr, 5000, 5000);
	CHECK(e != NULL && e->nfilters == 2);
	if(e == NULL || e->nfilters != 2)
		return;
	CHECK(e->filters[0].uid != 0 && e->filters[1].uid != 0);
	CHECK(e->filters[0].uid != e->filters[1].uid);
	CHECK(lease_table_find_uid(7) != NULL);
}
#endif
#endif

#ifdef ENABLE_NATPMP
/* A NAT-PMP request of a client for the internal port of its UPnP or PCP
 * mapping is refused (2, Not Authorized/Refused), and the mapping stays as
 * it was: only the protocol which made a mapping renews it. The client is
 * a socket on 127.0.0.1, which reads the answer the handler sends it. */
static void
test_natpmp_foreign(void)
{
	static const int kinds[] = { MAP_KIND_UPNP, MAP_KIND_PCP };
	unsigned char req[12] = {
		0, 2,		/* version 0, map TCP */
		0, 0,		/* reserved */
		0x13, 0x88,	/* internal port 5000 */
		0x13, 0x88,	/* suggested external port 5000 */
		0, 0, 0x1c, 0x20	/* lifetime 7200 s */
	};
	unsigned char resp[16];
	struct sockaddr_in client;
	socklen_t len = sizeof(client);
	struct lease_entry * row;
	unsigned int ts;
	size_t i;
	int family;
	int s;

	memset(&client, 0, sizeof(client));
	client.sin_family = AF_INET;
	client.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	s = socket(AF_INET, SOCK_DGRAM, 0);
	CHECK(s >= 0);
	if(s < 0)
		return;
	CHECK(bind(s, (struct sockaddr *)&client, sizeof(client)) == 0 &&
	      getsockname(s, (struct sockaddr *)&client, &len) == 0);
	for(i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++) {
		lease_table_clear();
		row = map4(kinds[i], 5000, 5000);
		map_pton("127.0.0.1", &family, &row->iaddr);
		reset();
		CHECK(upnp_redirect_internal(row) == 0);
		ts = row->timestamp;
		reset();
		ProcessIncomingNATPMPPacket(s, req, sizeof(req), &client);
		CHECK(recv(s, resp, sizeof(resp), MSG_DONTWAIT) == (ssize_t)sizeof(resp));
		CHECK(resp[1] == 128 + 2 && resp[2] == 0 && resp[3] == 2);
		CHECK(find4(5000) == row && row->kind == kinds[i] && row->timestamp == ts);
		CHECK(adds == 0 && deletes == 0 && updates == 0);
	}
	lease_table_clear();
	close(s);
}
#endif

int
main(void)
{
	ext_if_name = "wan";
#ifdef ENABLE_IPV6
	ext_if_name6 = "wan";
#endif
	test_add_half();
	test_expiry_retry();
	test_check_map();
	test_partial();
	test_kind();
#ifdef ENABLE_NATPMP
	test_natpmp_foreign();
#endif
#if defined(PCP_PEER) && defined(USE_NETFILTER)
	test_peer_retry();
#endif
#ifdef FW_MAP6
	test_map6();
	test_max_filters();
#ifdef ENABLE_LEASEFILE
	test_reload_uid();
#endif
#endif
	lease_table_clear();
	if(failures) {
		fprintf(stderr, "testcallers: %d check(s) failed\n", failures);
		return 1;
	}
	printf("testcallers: all tests passed\n");
	return 0;
}
