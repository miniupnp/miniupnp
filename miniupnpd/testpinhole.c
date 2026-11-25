/* MiniUPnP project
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

/* unit test of upnppinhole.c, on a fake backend: the rules each request
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

#if defined(ENABLE_UPNPPINHOLE) && (defined(USE_PF) || defined(USE_NETFILTER))

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

/* the fake backend: one rule per pinhole */
static struct rule {
	int used;
	unsigned short uid;
	char rhost[INET6_ADDRSTRLEN];	/* "" : any host */
	unsigned short rport;
	char iaddr[INET6_ADDRSTRLEN];
	unsigned short iport;
	int proto;
	unsigned int timestamp;
} rules[8];
static unsigned short next_uid = 1;

static int
rule_count(void)
{
	int i, n = 0;
	for(i = 0; i < 8; i++)
		n += rules[i].used;
	return n;
}

static struct rule *
rule_of_uid(unsigned short uid)
{
	int i;
	for(i = 0; i < 8; i++)
		if(rules[i].used && rules[i].uid == uid)
			return &rules[i];
	return NULL;
}

int
find_pinhole(const char * ifname, const char * rem_host, unsigned short rem_port,
             const char * int_client, unsigned short int_port, int proto,
             char * desc, int desc_len, unsigned int * timestamp)
{
	int i;
	(void)ifname;
	for(i = 0; i < 8; i++) {
		struct rule * r = &rules[i];
		if(r->used && r->rport == rem_port && r->iport == int_port &&
		   r->proto == proto && strcmp(r->iaddr, int_client) == 0 &&
		   strcmp(r->rhost, rem_host ? rem_host : "") == 0) {
			if(desc != NULL)
				snprintf(desc, desc_len, "%s", "x");
			if(timestamp != NULL)
				*timestamp = r->timestamp;
			return r->uid;
		}
	}
	return -2;
}

int
add_pinhole(const char * ifname, const char * rem_host, unsigned short rem_port,
            const char * int_client, unsigned short int_port, int proto,
            const char * desc, unsigned int timestamp)
{
	int i;
	(void)ifname; (void)desc;
	for(i = 0; i < 8 && rules[i].used; i++)
		;
	assert(i < 8);
	rules[i].used = 1;
	rules[i].uid = next_uid++;
	snprintf(rules[i].rhost, sizeof(rules[i].rhost), "%s", rem_host ? rem_host : "");
	rules[i].rport = rem_port;
	snprintf(rules[i].iaddr, sizeof(rules[i].iaddr), "%s", int_client);
	rules[i].iport = int_port;
	rules[i].proto = proto;
	rules[i].timestamp = timestamp;
	return rules[i].uid;
}

int
update_pinhole(unsigned short uid, unsigned int timestamp)
{
	struct rule * r = rule_of_uid(uid);
	if(r == NULL)
		return -1;
	r->timestamp = timestamp;
	return 0;
}

int
delete_pinhole(unsigned short uid)
{
	struct rule * r = rule_of_uid(uid);
	if(r == NULL)
		return -1;
	r->used = 0;
	return 0;
}

int
get_pinhole_info(unsigned short uid, char * rem_host, int rem_hostlen,
                 unsigned short * rem_port, char * int_client, int int_clientlen,
                 unsigned short * int_port, int * proto, char * desc, int desclen,
                 unsigned int * timestamp, u_int64_t * packets, u_int64_t * bytes)
{
	(void)uid; (void)rem_host; (void)rem_hostlen; (void)rem_port;
	(void)int_client; (void)int_clientlen; (void)int_port; (void)proto;
	(void)desc; (void)desclen; (void)timestamp; (void)packets; (void)bytes;
	return -2;
}

int
get_pinhole_uid_by_index(int index)
{
	(void)index;
	return -1;
}

int
clean_pinhole_list(unsigned int * next_timestamp,
                   void (*expired)(int proto, const struct in6_addr * iaddr,
                                   unsigned short iport,
                                   const struct in6_addr * raddr,
                                   unsigned short rport, unsigned short uid))
{
	(void)next_timestamp; (void)expired;
	return 0;
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
	/* the renewal of PCP: found by its key, renewed by the uid found */
	req = pcp_map("2001:db8::10", 4000, 3000);
	uid = upnp_find_inboundpinhole(req, NULL);
	assert(uid == rules[0].uid);
	assert(upnp_update_inboundpinhole(req, (unsigned short)uid) == 0);
	lease_table_free(req);
	assert(rule_count() == 1 && rules[0].timestamp == 3000 && row->timestamp == 3000);
	assert(row->nfilters == 0);
	/* the same request again through the add: the rule there is renewed */
	req = pcp_map("2001:db8::10", 4000, 4000);
	assert(upnp_add_inboundpinhole(req, NULL) == 1);
	row = lease_table_find_entry(IPPROTO_UDP, AF_INET6, &i, 4000, 4000);
	assert(rule_count() == 1 && rules[0].timestamp == 4000);
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
