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

/* the pinhole rule of a key in the rule cache, or NULL */
static rule_t *
find_rule(const char * rem_host, unsigned short rem_port,
          const char * int_client, unsigned short int_port, int proto)
{
	rule_t *p;
	struct in6_addr saddr, daddr;

	memset(&saddr, 0, sizeof(saddr));
	if (!pinhole_any_remote(rem_host) && inet_pton(AF_INET6, rem_host, &saddr) < 1) {
		syslog(LOG_WARNING, "Failed to parse INET6 address \"%s\"", rem_host);
		return NULL;
	}
	if (int_client == NULL || inet_pton(AF_INET6, int_client, &daddr) < 1) {
		syslog(LOG_WARNING, "Failed to parse INET6 address \"%s\"",
		       int_client ? int_client : "(null)");
		return NULL;
	}
	refresh_nft_cache_filter();
	LIST_FOREACH(p, &head_filter, entry) {
		if (p->type != RULE_FILTER || p->desc_len == 0)
			continue;
		if (proto == p->proto && rem_port == p->sport && int_port == p->dport &&
		    0 == memcmp(&saddr, &p->saddr6, sizeof(saddr)) &&
		    0 == memcmp(&daddr, &p->daddr6, sizeof(daddr)) &&
		    pinhole_label_desc(p->desc) != NULL)
			return p;
	}
	return NULL;
}

/*
ip saddr <rem_host> ip daddr <int_client> tcp sport <rem_port>  tcp dport <int_port>
*/
int
add_pinhole_rule(const char * ifname,
                 const char * rem_host, unsigned short rem_port,
                 const char * int_client, unsigned short int_port,
                 int proto, const char * desc, unsigned int timestamp)
{
	char comment[NFT_DESCR_SIZE];
	struct nftnl_rule *r;
	struct in6_addr rhost_addr, ihost_addr;
	struct in6_addr *rhost_addr_p = NULL;

	UNUSED(timestamp);	/* the map holds the expiry */

	d_printf(("add_pinhole_rule(%s, %s, %hu, %s, %hu, %d, %s, %u)\n",
	          ifname, rem_host, rem_port, int_client, int_port, proto, desc, timestamp));

	if (!pinhole_any_remote(rem_host)) {
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
	pinhole_label(comment, sizeof(comment), desc);
	r = rule_set_filter6(nft_ipv6_family, ifname, proto,
	                     rhost_addr_p, &ihost_addr,
	                     0, int_port, rem_port, comment, 0);
	return nft_send_rule(r, NFT_MSG_NEWRULE, RULE_CHAIN_FILTER) < 0 ? -1 : 0;
}

int
delete_pinhole_rule(const char * rem_host, unsigned short rem_port,
                    const char * int_client, unsigned short int_port, int proto)
{
	rule_t *p;

	d_printf(("delete_pinhole_rule()\n"));
	p = find_rule(rem_host, rem_port, int_client, int_port, proto);
	if (p == NULL)
		return -2;
	if (nft_send_rule(rule_del_handle(p), NFT_MSG_DELRULE, RULE_CHAIN_FILTER) < 0)
		return -1;
	return 0;
}

/* A label cannot change in place: the rule is deleted and added again. */
int
update_pinhole_rule(const char * ifname,
                    const char * rem_host, unsigned short rem_port,
                    const char * int_client, unsigned short int_port,
                    int proto, const char * desc, unsigned int timestamp)
{
	char ifname_rule[IFNAMSIZ];
	rule_t *p;

	d_printf(("update_pinhole_rule()\n"));
	p = find_rule(rem_host, rem_port, int_client, int_port, proto);
	if (p == NULL)
		return -2;
	/* the rule stays on the interface it was added on */
	if (p->ingress_ifidx != 0 && if_indextoname(p->ingress_ifidx, ifname_rule) != NULL)
		ifname = ifname_rule;
	if (nft_send_rule(rule_del_handle(p), NFT_MSG_DELRULE, RULE_CHAIN_FILTER) < 0)
		return -1;
	return add_pinhole_rule(ifname, rem_host, rem_port, int_client, int_port,
	                        proto, desc, timestamp);
}

int
get_pinhole_packets(const char * rem_host, unsigned short rem_port,
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
get_pinhole_rule_at(int index, char * rem_host, int rem_hostlen,
                    unsigned short * rem_port,
                    char * int_client, int int_clientlen,
                    unsigned short * int_port, int * proto,
                    char * desc, int desclen)
{
	rule_t *p;
	const char * d;
	static const struct in6_addr any;

	refresh_nft_cache_filter();
	LIST_FOREACH(p, &head_filter, entry) {
		if (p->type != RULE_FILTER || p->desc_len == 0 ||
		    (d = pinhole_label_desc(p->desc)) == NULL)
			continue;
		if (index-- > 0)
			continue;
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
	return -1;
}


#endif /* ENABLE_UPNPPINHOLE */
