/* $Id: nftpinhole.c,v 1.10 2025/04/26 12:58:38 nanard Exp $ */
/* MiniUPnP project
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * (c) 2012-2026 Thomas Bernard
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <limits.h>

#include "../upnputils.h"
#include "../memmap.h"
#include "nftpinhole.h"

#include <linux/version.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

#include <libmnl/libmnl.h>
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>

#include "tiny_nf_nat.h"

#include "config.h"
#include "../macros.h"
#include "nftnlrdr.h"
#include "../upnpglobalvars.h"

#include "nftnlrdr_misc.h"
#include "../memmap.h"

#ifdef DEBUG
#define d_printf(x) do { printf x; } while (0)
#else
#define d_printf(x)
#endif

#ifdef ENABLE_UPNPPINHOLE


void init_iptpinhole(void)
{
	return;
}

void shutdown_iptpinhole(void)
{
	return;
}

/* An index of the map6 rules of the rule cache by their key, built when
 * the cache changed since: a lookup of one rule does not walk all of them,
 * which made 70,000 renewals take 74 s with the fake kernel. Open
 * addressing, at most half full. */
static rule_t ** rule_index;
static size_t rule_index_size;	/* a power of 2, or 0 */
static uint32_t rule_index_epoch;
static int rule_index_valid;

static int
map6_rule(const rule_t * p)
{
	return p->type == RULE_FILTER && p->desc_len != 0 && map6_label_desc(p->desc) != NULL;
}

static uint32_t
rule_hash(int proto, unsigned short sport, unsigned short dport,
          const struct in6_addr * saddr, const struct in6_addr * daddr)
{
	/* FNV-1a over the key */
	uint32_t h = 2166136261u;
	size_t i;
#define HASH_BYTE(c) do { h ^= (unsigned char)(c); h *= 16777619u; } while (0)
	HASH_BYTE(proto);
	HASH_BYTE(sport >> 8); HASH_BYTE(sport);
	HASH_BYTE(dport >> 8); HASH_BYTE(dport);
	for (i = 0; i < 16; i++)
		HASH_BYTE(saddr->s6_addr[i]);
	for (i = 0; i < 16; i++)
		HASH_BYTE(daddr->s6_addr[i]);
#undef HASH_BYTE
	return h;
}

static int
rule_key_is(const rule_t * p, int proto, unsigned short sport, unsigned short dport,
            const struct in6_addr * saddr, const struct in6_addr * daddr)
{
	return proto == p->proto && sport == p->sport && dport == p->dport &&
	       memcmp(saddr, &p->saddr6, sizeof(*saddr)) == 0 &&
	       memcmp(daddr, &p->daddr6, sizeof(*daddr)) == 0;
}

/* build the index of the list as it is; 0, or -1 with no index */
static int
index_rules(struct rule_list * list)
{
	rule_t *p;
	size_t n = 0, size = 16;

	LIST_FOREACH(p, list, entry) {
		if (map6_rule(p))
			n++;
	}
	while (size < 2 * n)
		size *= 2;
	if (size != rule_index_size) {
		rule_t ** grown = realloc(rule_index, size * sizeof(*rule_index));
		if (grown == NULL) {
			rule_index_valid = 0;
			return -1;
		}
		rule_index = grown;
		rule_index_size = size;
	}
	memset(rule_index, 0, size * sizeof(*rule_index));
	LIST_FOREACH(p, list, entry) {
		size_t i;
		if (!map6_rule(p))
			continue;
		i = rule_hash(p->proto, p->sport, p->dport, &p->saddr6, &p->daddr6) & (size - 1);
		/* the first rule of a key, as the walk of the list found it */
		while (rule_index[i] != NULL &&
		       !rule_key_is(rule_index[i], p->proto, p->sport, p->dport, &p->saddr6, &p->daddr6))
			i = (i + 1) & (size - 1);
		if (rule_index[i] == NULL)
			rule_index[i] = p;
	}
	rule_index_epoch = nft_map6_cache_epoch();
	rule_index_valid = 1;
	return 0;
}

/* the pinhole rule of a key in the rule cache, or NULL */
static rule_t *
find_rule(const char * rem_host, unsigned short rem_port,
          const char * int_client, unsigned short int_port, int proto)
{
	rule_t *p;
	struct in6_addr saddr, daddr;
	struct rule_list * list;

	memset(&saddr, 0, sizeof(saddr));
	if (!map6_any_remote(rem_host) && inet_pton(AF_INET6, rem_host, &saddr) < 1) {
		syslog(LOG_WARNING, "Failed to parse INET6 address \"%s\"", rem_host);
		return NULL;
	}
	if (int_client == NULL || inet_pton(AF_INET6, int_client, &daddr) < 1) {
		syslog(LOG_WARNING, "Failed to parse INET6 address \"%s\"",
		       int_client ? int_client : "(null)");
		return NULL;
	}
	list = nft_map6_rules();
	if ((rule_index_valid && rule_index_epoch == nft_map6_cache_epoch()) ||
	    index_rules(list) == 0) {
		size_t i = rule_hash(proto, rem_port, int_port, &saddr, &daddr) & (rule_index_size - 1);
		while ((p = rule_index[i]) != NULL) {
			if (rule_key_is(p, proto, rem_port, int_port, &saddr, &daddr))
				return p;
			i = (i + 1) & (rule_index_size - 1);
		}
		return NULL;
	}
	LIST_FOREACH(p, list, entry) {
		if (map6_rule(p) && rule_key_is(p, proto, rem_port, int_port, &saddr, &daddr))
			return p;
	}
	return NULL;
}

/* delete rule p, which find_rule() gave: the cache stays valid when no
 * other program changed the ruleset meanwhile */
static int
delete_found(rule_t * p)
{
	uint32_t gen;
	int valid = nft_map6_cache_gen(&gen);
	if (nft_send_rule(rule_del_handle(p), NFT_MSG_DELRULE, RULE_CHAIN_FILTER) < 0)
		return -1;
	if (valid)
		nft_map6_cache_forget(p, gen);
	return 0;
}

/*
ip saddr <rem_host> ip daddr <int_client> tcp sport <rem_port>  tcp dport <int_port>
*/
int
add_map6_rule(const char * ifname,
                 const char * rem_host, unsigned short rem_port,
                 const char * int_client, unsigned short int_port,
                 int proto, const char * desc, unsigned int timestamp)
{
	char comment[NFT_DESCR_SIZE];
	struct nftnl_rule *r;
	struct in6_addr rhost_addr, ihost_addr;
	struct in6_addr *rhost_addr_p = NULL;

	UNUSED(timestamp);	/* the map holds the expiry */

	d_printf(("add_map6_rule(%s, %s, %hu, %s, %hu, %d, %s, %u)\n",
	          ifname, rem_host, rem_port, int_client, int_port, proto, desc, timestamp));

	if (!map6_any_remote(rem_host)) {
		if (inet_pton(AF_INET6, rem_host, &rhost_addr) == 1) {
			rhost_addr_p = &rhost_addr;
		} else {
			syslog(LOG_WARNING, "Failed to parse INET6 address \"%s\"", rem_host);
			return -1;
		}
	}
	if (inet_pton(AF_INET6, int_client, &ihost_addr) != 1) {
		syslog(LOG_WARNING, "Failed to parse INET6 address \"%s\"", int_client);
		return -1;
	}
	map6_label(comment, sizeof(comment), desc);
	r = rule_set_filter6(nft_ipv6_family, ifname, proto,
	                     rhost_addr_p, &ihost_addr,
	                     0, int_port, rem_port, comment, 0);
	return nft_send_rule(r, NFT_MSG_NEWRULE, RULE_CHAIN_FILTER) < 0 ? -1 : 0;
}

int
delete_map6_rule(const char * rem_host, unsigned short rem_port,
                    const char * int_client, unsigned short int_port, int proto)
{
	rule_t *p;

	d_printf(("delete_map6_rule()\n"));
	p = find_rule(rem_host, rem_port, int_client, int_port, proto);
	if (p == NULL)
		return -2;
	return delete_found(p);
}

/* A label cannot change in place: the rule is deleted and added again. */
int
update_map6_rule(const char * ifname,
                    const char * rem_host, unsigned short rem_port,
                    const char * int_client, unsigned short int_port,
                    int proto, const char * desc, unsigned int timestamp)
{
	char ifname_rule[IFNAMSIZ];
	rule_t *p;

	d_printf(("update_map6_rule()\n"));
	p = find_rule(rem_host, rem_port, int_client, int_port, proto);
	if (p == NULL)
		return -2;
	/* the rule stays on the interface it was added on */
	if (p->ingress_ifidx != 0 && if_indextoname(p->ingress_ifidx, ifname_rule) != NULL)
		ifname = ifname_rule;
	if (delete_found(p) < 0)
		return -1;
	return add_map6_rule(ifname, rem_host, rem_port, int_client, int_port,
	                        proto, desc, timestamp);
}

int
get_map6_packets(const char * rem_host, unsigned short rem_port,
                    const char * int_client, unsigned short int_port,
                    int proto, u_int64_t * packets)
{
	rule_t *p = find_rule(rem_host, rem_port, int_client, int_port, proto);
	if (p == NULL)
		return -2;
	if (packets)
		*packets = p->packets;
	return 0;
}

int
get_map6_rule_at(int index, char * rem_host, int rem_hostlen,
                    unsigned short * rem_port,
                    char * int_client, int int_clientlen,
                    unsigned short * int_port, int * proto,
                    char * desc, int desclen)
{
	rule_t *p;
	const char * d;
	static const struct in6_addr any;
	/* where the last call stopped: a walk by index, 0, 1, 2..., then goes
	 * on from there, not from the start each time */
	static rule_t * last;
	static int last_index = -1;
	static uint32_t last_epoch;
	struct rule_list * list = nft_map6_rules();
	int start = 0;

	p = LIST_FIRST(list);
	if (last != NULL && last_epoch == nft_map6_cache_epoch() && index > last_index) {
		p = LIST_NEXT(last, entry);
		start = last_index + 1;
	}
	for (; p != NULL; p = LIST_NEXT(p, entry)) {
		if (!map6_rule(p))
			continue;
		d = map6_label_desc(p->desc);
		if (start++ < index)
			continue;
		last = p;
		last_index = index;
		last_epoch = nft_map6_cache_epoch();
		if (rem_host && rem_hostlen > 0) {
			rem_host[0] = '\0';
			if (memcmp(&p->saddr6, &any, sizeof(any)) != 0)
				inet_ntop(AF_INET6, &p->saddr6, rem_host, rem_hostlen);
		}
		if (rem_port)
			*rem_port = p->sport;
		if (int_client)
			inet_ntop(AF_INET6, &p->daddr6, int_client, int_clientlen);
		if (int_port)
			*int_port = p->dport;
		if (proto)
			*proto = p->proto;
		if (desc && desclen > 0) {
			strncpy(desc, d, desclen);
			desc[desclen - 1] = '\0';
		}
		return 0;
	}
	last = NULL;
	return -1;
}


#endif /* ENABLE_UPNPPINHOLE */
