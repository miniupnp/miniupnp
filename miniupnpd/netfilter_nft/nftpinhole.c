/* $Id: iptpinhole.c,v 1.19 2018/04/22 19:36:58 nanard Exp $ */
/* MiniUPnP project
 * http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * (c) 2012-2018 Thomas Bernard
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <limits.h>

#include "../upnputils.h"
#include "nftpinhole.h"

#include <linux/version.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

#include <libmnl/libmnl.h>
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>

#include "tiny_nf_nat.h"

#include "../macros.h"
#include "../config.h"
#include "nftnlrdr.h"
#include "../upnpglobalvars.h"

#include "nftnlrdr_misc.h"

#ifdef DEBUG
#define d_printf(x) do { printf x; } while (0)
#else
#define d_printf(x)
#endif

#ifdef ENABLE_UPNPPINHOLE

static int next_uid = 1;

#define PINEHOLE_LABEL_FORMAT "pinhole-%d ts-%u: %s"
#define PINEHOLE_LABEL_FORMAT_SKIPDESC "pinhole-%d ts-%u: %*s"

void init_iptpinhole(void)
{
	return;
}

void shutdown_iptpinhole(void)
{
	return;
}

/*
ip saddr <rem_host> ip daddr <int_client> tcp sport <rem_port>  tcp dport <int_port> 
*/
int add_pinhole(const char * ifname,
                const char * rem_host, unsigned short rem_port,
                const char * int_client, unsigned short int_port,
                int proto, const char * desc, unsigned int timestamp)
{
	int uid, res;
	char comment[NFT_DESCR_SIZE];

	struct nftnl_rule *r = NULL;
	struct in6_addr rhost_addr, ihost_addr;
	struct in6_addr *rhost_addr_p;

	UNUSED(rem_host);
	UNUSED(rem_port);

	uid = next_uid;

	d_printf(("add_pinhole(%s, %s, %s, %d, %d, %d, %s)\n",
	          ifname, rem_host, int_client, rem_port, int_port, proto, desc));

	if (rem_host && rem_host[0] != '\0' && rem_host[0] != '*') {
		inet_pton(AF_INET6, rem_host, &rhost_addr);
		rhost_addr_p = &rhost_addr;
	} else {
		rhost_addr_p = NULL;
	}

	inet_pton(AF_INET6, int_client, &ihost_addr);

	snprintf(comment, NFT_DESCR_SIZE,
		         PINEHOLE_LABEL_FORMAT, uid, timestamp, desc);

	r = rule_set_filter6(NFPROTO_INET, ifname, proto,
			    rhost_addr_p, &ihost_addr,
				0, int_port, rem_port, comment, 0);

	res = nft_send_request(r, NFT_MSG_NEWRULE, RULE_CHAIN_FILTER);

	if (res < 0)
		return -1;

	if (++next_uid >= 65535) {
		next_uid = 1;
	}

	return uid;
}

int
find_pinhole(const char * ifname,
             const char * rem_host, unsigned short rem_port,
             const char * int_client, unsigned short int_port,
             int proto,
             char *desc, int desc_len, unsigned int * timestamp)
{
	rule_t *p;
	struct in6_addr saddr;
	struct in6_addr daddr;
	int uid;
	unsigned int ts;
	UNUSED(ifname);

	if (rem_host && (rem_host[0] != '\0')) {
		inet_pton(AF_INET6, rem_host, &saddr);
	} else {
		memset(&saddr, 0, sizeof(struct in6_addr));
	}
	inet_pton(AF_INET6, int_client, &daddr);

	d_printf(("find_pinhole()\n"));
	reflesh_nft_cache_filter();

	LIST_FOREACH(p, &head_filter, entry) {

		// Only forward entries
		if (p->type != RULE_FILTER)
			continue;

		if (p->desc_len == 0)
			continue;

		if ((proto == p->proto) && (rem_port == ntohs(p->rport))
		   && (0 == memcmp(&saddr, &p->iaddr6, sizeof(struct in6_addr)))
		   && (int_port == ntohs(p->eport)) &&
		   (0 == memcmp(&daddr, &p->iaddr6, sizeof(struct in6_addr)))) {

			if (sscanf(p->desc, PINEHOLE_LABEL_FORMAT_SKIPDESC, &uid, &ts) != 2) {
				syslog(LOG_DEBUG, "rule with label '%s' is not a IGD pinhole", p->desc);
				continue;
			}

			if (timestamp)
				*timestamp = ts;
	
			if (desc) {
				char * pd = strchr(p->desc, ':');
				if(pd) {
					pd += 2;
					strncpy(desc, pd, desc_len);
				}
			}

			return uid;
		}
	}

	return -2;	/* not found */
}

int
delete_pinhole(unsigned short uid)
{
	rule_t *p;
	struct nftnl_rule *r;
	char label_start[NFT_DESCR_SIZE];
	char tmp_label[NFT_DESCR_SIZE];

	snprintf(label_start, sizeof(label_start),
	         "pinhole-%hu", uid);

	d_printf(("find_pinhole()\n"));
	reflesh_nft_cache_filter();

	LIST_FOREACH(p, &head_filter, entry) {
		// Only forward entries
		if (p->type != RULE_FILTER)
			continue;

		if (p->desc_len == 0)
			continue;

		strncpy(tmp_label, p->desc, p->desc_len);
		strtok(tmp_label, " ");
		if (0 == strcmp(tmp_label, label_start)) {
			r = rule_del_handle(p);
			nft_send_request(r, NFT_MSG_DELRULE, RULE_CHAIN_FILTER);
			return 0;
		}
	}

	return -2;
}

int
update_pinhole(unsigned short uid, unsigned int timestamp)
{
	char iaddr[INET6_ADDRSTRLEN];
	char raddr[INET6_ADDRSTRLEN];
	char label_start[NFT_DESCR_SIZE];
	char tmp_label[NFT_DESCR_SIZE];
	char desc[NFT_DESCR_SIZE];
	char ifname[IFNAMSIZ];
	char * tmp_p;
	uint32_t ext_if_indx;
	int proto;
	unsigned short iport, rport;
	rule_t *p;

	d_printf(("update_pinhole()\n"));

	reflesh_nft_cache_filter();

	proto = -1;

	LIST_FOREACH(p, &head_filter, entry) {
		// Only forward entries
		if (p->type != RULE_FILTER)
			continue;

		if (p->desc_len == 0)
			continue;

		strncpy(tmp_label, p->desc, p->desc_len);
		strtok(tmp_label, " ");
		if (0 == strcmp(tmp_label, label_start)) {
			/* Source IP Address */
			inet_ntop(AF_INET6, &p->rhost6, raddr, sizeof(raddr));

			/* Source Port */
			rport = p->eport;

			/* Destination IP Address */
			inet_ntop(AF_INET6, &p->iaddr6, iaddr, sizeof(iaddr));

			/* Destination Port */
			iport = p->iport;

			proto = p->proto;

			ext_if_indx = p->ingress_ifidx;
			if_indextoname(ext_if_indx, ifname);

			tmp_p = tmp_label;
			strsep(&tmp_p, " ");
			if (tmp_p) {
				strncpy(desc, tmp_p, NFT_DESCR_SIZE);
			} else {
				desc[0] = '\0';
			}

			break;
		}
	}

	if (proto == -1)
		return -2;

	delete_pinhole(uid);
	add_pinhole(ifname, raddr, rport, iaddr, iport, proto, desc, timestamp);

	return 0;
}

int
get_pinhole_info(unsigned short uid,
                 char * rem_host, int rem_hostlen,
                 unsigned short * rem_port,
                 char * int_client, int int_clientlen,
                 unsigned short * int_port,
                 int * proto, char * desc, int desclen,
                 unsigned int * timestamp,
                 u_int64_t * packets, u_int64_t * bytes)
{
	rule_t *p;
	unsigned int ts;
	char label_start[NFT_DESCR_SIZE];
	char tmp_label[NFT_DESCR_SIZE];

	snprintf(label_start, sizeof(label_start),
	         "pinhole-%hu", uid);

	d_printf(("get_pinhole_info()\n"));
	reflesh_nft_cache_filter();

	LIST_FOREACH(p, &head_filter, entry) {
		// Only forward entries
		if (p->type != RULE_FILTER)
			continue;

		if (p->desc_len == 0)
			continue;

		strncpy(tmp_label, p->desc, p->desc_len);
		strtok(tmp_label, " ");
		if (0 == strcmp(tmp_label, label_start)) {
			/* Source IP Address */
			if (rem_host && (rem_host[0] != '\0')) {
				if(inet_ntop(AF_INET6, &p->rhost6, rem_host, rem_hostlen) == NULL)
					return -1;
			}

			/* Source Port */
			if (rem_port)
				*rem_port = p->rport;

			/* Destination IP Address */
			if (int_client) {
				if(inet_ntop(AF_INET6, &p->iaddr6, int_client, int_clientlen) == NULL)
					return -1;
			}

			/* Destination Port */
			if (int_port)
				*int_port = p->eport;

			if (proto)
				*proto = p->proto;

			if (timestamp) {
				if (sscanf(p->desc, PINEHOLE_LABEL_FORMAT_SKIPDESC,(int *) &uid, &ts) != 2) {
					syslog(LOG_DEBUG, "rule with label '%s' is not a IGD pinhole", p->desc);
					continue;
				}

				*timestamp = ts;
			}

			if (desc)
				strncpy(desc, p->desc, desclen);

			if (packets || bytes) {
				if (packets)
					*packets = p->packets;
				if (bytes)
					*bytes = p->bytes;
			}

			break;
		}
	}

	d_printf(("end_pinhole_info()\n"));

	return 0;
}

int get_pinhole_uid_by_index(int index)
{
	UNUSED(index);
	return -42;
}

int
clean_pinhole_list(unsigned int * next_timestamp)
{
	rule_t *p;
	struct nftnl_rule *r;
	time_t current_time;
	unsigned int ts;
	int uid;
	unsigned int min_ts = UINT_MAX;
	int min_uid = INT_MAX, max_uid = -1;
	int n = 0;

	current_time = upnp_time();

	d_printf(("clean_pinhole_list()\n"));
	reflesh_nft_cache_filter();

	LIST_FOREACH(p, &head_filter, entry) {
		// Only forward entries
		if (p->type != RULE_FILTER)
			continue;

		if (p->desc_len == 0)
			continue;

		if (sscanf(p->desc, PINEHOLE_LABEL_FORMAT_SKIPDESC, &uid, &ts) != 2) {
			syslog(LOG_DEBUG, "rule with label '%s' is not a IGD pinhole", p->desc);
			continue;
		}

		if (ts <= (unsigned int)current_time) {
			syslog(LOG_INFO, "removing expired pinhole '%s'", p->desc);
			r = rule_del_handle(p);
			nft_send_request(r, NFT_MSG_DELRULE, RULE_CHAIN_FILTER);
			n++;
		} else {
			if (uid > max_uid)
				max_uid = uid;
			else if (uid < min_uid)
				min_uid = uid;
			if (ts < min_ts)
				min_ts = ts;
		}
	}

	if (next_timestamp && (min_ts != UINT_MAX))
		*next_timestamp = min_ts;

	if (max_uid > 0) {
		if (((min_uid - 32000) <= next_uid) && (next_uid <= max_uid)) {
			next_uid = max_uid + 1;
		}

		if (next_uid >= 65535) {
			next_uid = 1;
		}
	}

	return n;	/* number of rules removed */
}

#endif /* ENABLE_UPNPPINHOLE */
