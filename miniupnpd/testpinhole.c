/* MiniUPnP project
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

/* unit test of upnppinhole.c, on a fake fwsync: the rules each request
 * puts in the firewall, and the row it leaves in the lease table */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "config.h"
#include "upnppinhole.h"
#include "memmap.h"
#include "fwsync.h"
#include "upnpglobalvars.h"

#if defined(ENABLE_UPNPPINHOLE) && defined(FW_MAP6)

/* what upnppinhole.c takes from the daemon */
const char * ext_if_name6 = "wan0";
const char * lease_file = NULL;
const char * lease_file6 = NULL;

time_t
upnp_time(void)
{
	return 1000;
}

int
proto_atoi(const char * protocol)
{
	return strcmp(protocol, "TCP") == 0 ? IPPROTO_TCP : IPPROTO_UDP;
}

const char *
proto_itoa(int proto)
{
	return proto == IPPROTO_TCP ? "TCP" : "UDP";
}

int firewall_trust = FW_TRUST_CHECK;

/* the fake fwsync: a map6 row has one rule per filter, and a row with no
 * filter one rule of any remote */
static struct rule {
	int used;
	char rhost[INET6_ADDRSTRLEN];	/* "" : any host */
	unsigned short rport;
	char iaddr[INET6_ADDRSTRLEN];
	unsigned short iport;
	int proto;
} rules[8];

static int
rule_count(void)
{
	int i, n = 0;
	for(i = 0; i < 8; i++)
		n += rules[i].used;
	return n;
}

/* the rule of filter i of e, or of any remote if e has no filter */
static void
rule_of(const struct lease_entry * e, int i, struct rule * r)
{
	memset(r, 0, sizeof(*r));
	if(e->nfilters > 0 && e->filters[i].prefix != 0)
		inet_ntop(AF_INET6, &e->filters[i].raddr, r->rhost, sizeof(r->rhost));
	r->rport = e->nfilters > 0 ? e->filters[i].rport : 0;
	inet_ntop(AF_INET6, &e->iaddr, r->iaddr, sizeof(r->iaddr));
	r->iport = e->iport;
	r->proto = e->proto;
}

static struct rule *
find_rule(const struct lease_entry * e, int i)
{
	struct rule k;
	int j;

	rule_of(e, i, &k);
	for(j = 0; j < 8; j++) {
		struct rule * r = &rules[j];
		if(r->used && r->rport == k.rport && r->iport == k.iport &&
		   r->proto == k.proto && strcmp(r->iaddr, k.iaddr) == 0 &&
		   strcmp(r->rhost, k.rhost) == 0)
			return r;
	}
	return NULL;
}

static int
nrules(const struct lease_entry * e)
{
	return e->nfilters > 0 ? e->nfilters : 1;
}

void
fw_change_init(struct fw_change * c, enum fw_op op,
               const struct lease_entry * row, const struct lease_entry * old)
{
	memset(c, 0, sizeof(*c));
	c->op = op;
	c->row = row;
	c->old = old;
}

int
fw_sync(struct fw_change * changes, int n)
{
	int i, j, k;

	for(i = 0; i < n; i++) {
		struct fw_change * c = &changes[i];
		struct rule * r;
		if(c->old != NULL && c->op != FW_ADD) {
			for(j = 0; j < nrules(c->old); j++) {
				if((r = find_rule(c->old, j)) != NULL)
					r->used = 0;
			}
		}
		if(c->row != NULL && c->op != FW_DELETE) {
			for(j = 0; j < nrules(c->row); j++) {
				if(find_rule(c->row, j) != NULL)
					continue;
				for(k = 0; k < 8 && rules[k].used; k++)
					;
				assert(k < 8);
				rule_of(c->row, j, &rules[k]);
				rules[k].used = 1;
			}
		}
		c->applied = FW_APPLIED;
	}
	return 0;
}

int
fw_map6_rule(const struct lease_entry * e, int i)
{
	return find_rule(e, i) != NULL ? 0 : -2;
}

int
fw_map6_packets(const struct lease_entry * e, int i, u_int64_t * packets)
{
	*packets = 0;
	return fw_map6_rule(e, i);
}

static struct in6_addr
addr(const char * s)
{
	struct in6_addr a;
	assert(inet_pton(AF_INET6, s, &a) == 1);
	return a;
}

/* an IPv6 PCP MAP request without FILTER, as pcpserver.c fills it: no
 * filter */
static struct lease_entry *
pcp_map(const char * iaddr, unsigned short iport, unsigned int timestamp)
{
	struct lease_entry * e = lease_table_new(0);
	unsigned char nonce[MAP_NONCE_LEN] = { 1, 2, 3 };
	assert(e != NULL);
	lease_entry_set_kind(e, MAP_KIND_PCP, nonce);
	e->family = AF_INET6;
	e->proto = IPPROTO_UDP;
	e->iaddr = e->eaddr = addr(iaddr);
	e->iport = e->eport = iport;
	e->timestamp = timestamp;
	return e;
}

/* A PCP map without FILTER: a row of no filter, and one firewall rule of
 * any remote, found, renewed and deleted by its key. */
static void
test_pcp_no_filter(void)
{
	struct in6_addr i = addr("2001:db8::10");
	struct lease_entry * req, * row, del;
	int uid;

	lease_table_clear();
	req = pcp_map("2001:db8::10", 4000, 2000);
	assert(upnp_add_inboundpinhole(req, NULL) == 1);	/* the table takes req */
	row = lease_table_find_entry(IPPROTO_UDP, AF_INET6, &i, 4000, 4000);
	assert(row == req && row->nfilters == 0 && lease_table_filter_count() == 0);
	assert(rule_count() == 1 && rules[0].rhost[0] == '\0' && rules[0].rport == 0);
	assert(strcmp(rules[0].iaddr, "2001:db8::10") == 0 && rules[0].iport == 4000);
	/* the renewal of PCP: found by its key, which has no uid */
	req = pcp_map("2001:db8::10", 4000, 3000);
	uid = upnp_find_inboundpinhole(req, NULL);
	assert(uid == 0);
	assert(upnp_update_inboundpinhole(req, (unsigned short)uid) == 0);
	lease_table_free(req);
	assert(rule_count() == 1 && row->timestamp == 3000);
	assert(row->nfilters == 0);
	/* the same request again through the add: the rule there is renewed */
	req = pcp_map("2001:db8::10", 4000, 4000);
	assert(upnp_add_inboundpinhole(req, NULL) == 1);
	row = lease_table_find_entry(IPPROTO_UDP, AF_INET6, &i, 4000, 4000);
	assert(rule_count() == 1);
	assert(lease_table_count() == 1 && row->nfilters == 0 && row->timestamp == 4000);
	/* the delete of PCP */
	lease_entry_init(&del, MAP_KIND_PCP, NULL);
	del.family = AF_INET6;
	del.proto = IPPROTO_UDP;
	del.iaddr = del.eaddr = i;
	del.iport = del.eport = 4000;
	uid = upnp_find_inboundpinhole(&del, NULL);
	assert(uid >= 0);
	assert(upnp_delete_inboundpinhole(&del, (unsigned short)uid) == 0);
	assert(rule_count() == 0 && lease_table_count() == 0);
	lease_table_clear();
}

/* A UPnP pinhole keeps its one filter, which carries the uid of its rule. */
static void
test_upnp_pinhole(void)
{
	struct lease_entry * req, del;
	struct map_filter f;
	unsigned short uid = 0;

	lease_table_clear();
	req = lease_table_new(1);
	assert(req != NULL);
	lease_entry_set_kind(req, MAP_KIND_UPNP, NULL);
	req->family = AF_INET6;
	req->proto = IPPROTO_TCP;
	req->iaddr = req->eaddr = addr("2001:db8::20");
	req->iport = req->eport = 5000;
	req->timestamp = 2000;
	assert(map_filter_set(&req->filters[0], "2001:db8:1::1", 80) == 0);
	assert(upnp_add_inboundpinhole(req, &uid) == 1);
	assert(uid != 0 && req->nfilters == 1 && req->filters[0].uid == uid);
	assert(lease_table_find_uid(uid) == &req->filters[0]);
	assert(rule_count() == 1 && strcmp(rules[0].rhost, "2001:db8:1::1") == 0 &&
	       rules[0].rport == 80);
	/* DeletePinhole: by the uid */
	lease_entry_init(&del, MAP_KIND_UPNP, NULL);
	del.family = AF_INET6;
	del.proto = IPPROTO_TCP;
	del.iaddr = del.eaddr = addr("2001:db8::20");
	del.iport = del.eport = 5000;
	map_filter_set(&f, "2001:db8:1::1", 80);
	f.uid = uid;
	del.filters = &f;
	del.nfilters = 1;
	assert(upnp_delete_inboundpinhole(&del, uid) == 0);
	assert(rule_count() == 0 && lease_table_count() == 0);
	lease_table_clear();
}

int
main(void)
{
	test_pcp_no_filter();
	test_upnp_pinhole();
	printf("testpinhole: OK\n");
	return 0;
}

#else

int
main(void)
{
	printf("testpinhole: no IPv6 pinholes in this build, skipped\n");
	return 0;
}

#endif
