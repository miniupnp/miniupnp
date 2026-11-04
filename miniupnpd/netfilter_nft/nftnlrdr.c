/* $Id: nftnlrdr.c,v 1.15 2024/03/11 23:28:21 nanard Exp $
 * vim: tabstop=4 shiftwidth=4 noexpandtab
 * MiniUPnP project
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * (c) 2015 Tomofumi Hayashi
 * (c) 2019 Sven Auhagen
 * (c) 2019 Paul Chambers
 * (c) 2020-2025 Thomas Bernard
 *
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution.
 */
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
#include <net/if.h>

#include <linux/version.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

#include <libmnl/libmnl.h>
#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>

#include "tiny_nf_nat.h"

#include "config.h"
#include "../macros.h"
#include "../commonrdr.h"
#include "../getifaddr.h"
#include "../peer_lease.h"
#include "nftnlrdr.h"

#include "nftnlrdr_misc.h"
#include "../pcp_filter.h"

#ifdef DEBUG
#define d_printf(x) do { printf x; } while (0)
#else
#define d_printf(x)
#endif

/* list to keep timestamps for port mappings having a lease duration */
struct timestamp_entry {
	struct timestamp_entry * next;
	unsigned int timestamp;
	unsigned short eport;
	short protocol;
};

static struct timestamp_entry * timestamp_list = NULL;

#define NAT_CHAIN_TYPE		"nat"
#define FILTER_CHAIN_TYPE	"filter"

/* init and shutdown functions */
int
init_redirect(void)
{
	int result;

	/* requires elevated privileges */
	result = nft_mnl_connect();

	return result;
}

void
shutdown_redirect(void)
{
	peer_lease_free_all();
	nft_mnl_disconnect();
}

/**
 * used by the core to override default chain names if specified in config file
 * @param param which string to set
 * @param string the new name to use. Do not dispose after setting (i.e. use strdup if not static).
 * @return 0 if successful
 */
int
set_rdr_name(rdr_name_type param, const char *string)
{
	if (string == NULL || strlen(string) > 30 || string[0] == '\0') {
		syslog(LOG_ERR, "%s(): invalid string argument '%s'", "set_rdr_name", string);
		return -1;
	}
	switch (param) {
	case RDR_TABLE_NAME:
		nft_table = string;
		break;
	case RDR_NAT_TABLE_NAME:
		nft_nat_table = string;
		break;
	case RDR_NAT_PREROUTING_CHAIN_NAME:
		nft_prerouting_chain = string;
		break;
	case RDR_NAT_POSTROUTING_CHAIN_NAME:
		nft_postrouting_chain = string;
		break;
	case RDR_FORWARD_CHAIN_NAME:
		nft_forward_chain = string;
		break;
	case RDR_FAMILY_SPLIT:
		if(strcmp(string, "yes") == 0) {
			nft_nat_family = NFPROTO_IPV4;
			nft_ipv4_family = NFPROTO_IPV4;
			nft_ipv6_family = NFPROTO_IPV6;
			syslog(LOG_INFO, "using IPv4/IPv6 Table");
		}
		break;
	default:
		syslog(LOG_ERR, "%s(): tried to set invalid string parameter: %d", "set_rdr_name", param);
		return -2;
	}
	return 0;
}

static unsigned int
get_timestamp(unsigned short eport, int proto)
{
	struct timestamp_entry * e;
	e = timestamp_list;
	while(e) {
		if(e->eport == eport && e->protocol == (short)proto) {
			syslog(LOG_DEBUG, "timestamp entry found (%hu, %d, %u)", eport, proto, e->timestamp);
			return e->timestamp;
		}
		e = e->next;
	}
	syslog(LOG_WARNING, "get_timestamp(%hu, %d) no entry found", eport, proto);
	return 0;
}

static void
remove_timestamp_entry(unsigned short eport, int proto)
{
	struct timestamp_entry * e;
	struct timestamp_entry * * p;
	p = &timestamp_list;
	e = *p;
	while(e) {
		if(e->eport == eport && e->protocol == (short)proto) {
			syslog(LOG_DEBUG, "timestamp entry removed (%hu, %d, %u)", eport, proto, e->timestamp);
			/* remove the entry */
			*p = e->next;
			free(e);
			return;
		}
		p = &(e->next);
		e = *p;
	}
	syslog(LOG_WARNING, "remove_timestamp_entry(%hu, %d) no entry found", eport, proto);
}

static void
add_timestamp_entry(unsigned short eport, int proto, unsigned timestamp)
{
	struct timestamp_entry * tmp;
	tmp = malloc(sizeof(struct timestamp_entry));
	if(tmp)
	{
		tmp->next = timestamp_list;
		tmp->timestamp = timestamp;
		tmp->eport = eport;
		tmp->protocol = (short)proto;
		timestamp_list = tmp;
		syslog(LOG_DEBUG, "timestamp entry added (%hu, %d, %u)", eport, proto, timestamp);
	}
	else
	{
		syslog(LOG_ERR, "add_timestamp_entry() malloc(%lu) error",
		       sizeof(struct timestamp_entry));
	}
}

int
add_redirect_rule2(const char * ifname,
		   const char * rhost, unsigned short eport,
		   const char * iaddr, unsigned short iport, int proto,
		   const char * desc, unsigned int timestamp)
{
	int ret;
	struct nftnl_rule *r;
	in_addr_t rhost_addr = 0;

	d_printf(("add redirect rule2(%s, %s, %u, %s, %u, %d, %s)!\n",
	          ifname, rhost, eport, iaddr, iport, proto, desc));

	if (rhost != NULL && strcmp(rhost, "") != 0 && strcmp(rhost, "*") != 0) {
		rhost_addr = inet_addr(rhost);
	}
	r = rule_set_dnat(nft_nat_family, ifname, proto,
	                  rhost_addr, eport,
	                  inet_addr(iaddr), iport,  desc, NULL);

	ret = nft_send_rule(r, NFT_MSG_NEWRULE, RULE_CHAIN_REDIRECT);
	if (ret >= 0) {
		add_timestamp_entry(eport, proto, timestamp);
	}
	return ret;
}

/*
 * This function submit the rule as following:
 * nft add rule nat miniupnpd-pcp-peer ip
 *    saddr <iaddr> ip daddr <rhost> tcp sport <iport>
 *    tcp dport <rport> snat <eaddr>:<eport>
 */
int
add_peer_redirect_rule2(const char * ifname,
			const char * rhost, unsigned short rport,
			const char * eaddr, unsigned short eport,
			const char * iaddr, unsigned short iport, int proto,
			const char * desc, unsigned int timestamp)
{
	struct nftnl_rule *r;
	rule_t *old;
	struct in_addr ia, ra, ea;
	char extip[INET_ADDRSTRLEN];
	unsigned int old_timestamp;
	int had_lease;
	int ret;

	d_printf(("add peer redirect rule2()!\n"));

	if (inet_pton(AF_INET, iaddr, &ia) != 1 || inet_pton(AF_INET, rhost, &ra) != 1)
		return -1;
	if (eaddr != NULL && eaddr[0] != '\0') {
		if (inet_pton(AF_INET, eaddr, &ea) != 1)
			return -1;
	} else if (getifaddr(ifname, extip, sizeof(extip), &ea, NULL) < 0) {
		return -1;	/* no address on the external interface */
	}

	had_lease = peer_lease_exists(ia.s_addr, iport, ra.s_addr, rport, proto);
	old_timestamp = peer_lease_get(ia.s_addr, iport, ra.s_addr, rport, proto);
	if (peer_lease_set(ia.s_addr, iport, ra.s_addr, rport, proto, timestamp) < 0)
		return -1;

	r = rule_set_snat(nft_nat_family, proto,
	                  ra.s_addr, rport,
	                  ea.s_addr, eport,
	                  ia.s_addr, iport, desc, NULL);

	if (r == NULL) {
		if (had_lease)
			peer_lease_set(ia.s_addr, iport, ra.s_addr, rport, proto, old_timestamp);
		else
			peer_lease_remove(ia.s_addr, iport, ra.s_addr, rport, proto);
		return -1;
	}
	/* Refresh an existing endpoint without accumulating duplicate SNAT rules. */
	refresh_nft_cache_peer();
	LIST_FOREACH(old, &head_peer, entry) {
		if (old->saddr == ia.s_addr && old->sport == iport &&
		    old->daddr == ra.s_addr && old->dport == rport &&
		    old->proto == proto) {
			nftnl_rule_set_u64(r, NFTNL_RULE_HANDLE, old->handle);
			break;
		}
	}
	ret = nft_send_rule(r, NFT_MSG_NEWRULE, RULE_CHAIN_PEER);
	if (ret < 0) {
		/* back to the lease we had */
		if (had_lease)
			peer_lease_set(ia.s_addr, iport, ra.s_addr, rport, proto, old_timestamp);
		else
			peer_lease_remove(ia.s_addr, iport, ra.s_addr, rport, proto);
	}
	return ret;
}

/*
 * This function submit the rule as following:
 * nft add rule filter miniupnpd
 *    ip daddr <iaddr> tcp dport <iport> accept
 *
 */
int
add_filter_rule2(const char * ifname,
		 const char * rhost, const char * iaddr,
		 unsigned short eport, unsigned short iport,
		 int proto, const char * desc)
{
	struct nftnl_rule *r = NULL;
	in_addr_t rhost_addr = 0;

	d_printf(("add_filter_rule2(%s, %s, %s, %d, %d, %d, %s)\n",
	          ifname, rhost, iaddr, eport, iport, proto, desc));

	if (rhost != NULL && strcmp(rhost, "") != 0 && strcmp(rhost, "*") != 0) {
		rhost_addr = inet_addr(rhost);
	}
	r = rule_set_filter(nft_nat_family, ifname, proto,
	                    rhost_addr, inet_addr(iaddr),
	                    eport, iport, 0,
	                    desc, 0);

	return nft_send_rule(r, NFT_MSG_NEWRULE, RULE_CHAIN_FILTER);
}

/*
 * add_peer_dscp_rule2() is not supported due to nft does not support
 * dscp set.
 */
int
add_peer_dscp_rule2(const char * ifname,
		    const char * rhost, unsigned short rport,
		    unsigned char dscp,
		    const char * iaddr, unsigned short iport, int proto,
		    const char * desc, unsigned int timestamp)
{
	UNUSED(ifname); UNUSED(rhost); UNUSED(rport);
	UNUSED(dscp); UNUSED(iaddr); UNUSED(iport); UNUSED(proto);
	UNUSED(desc); UNUSED(timestamp);
	syslog(LOG_ERR, "add_peer_dscp_rule2: not supported");
	return 0;
}

int
delete_filter_rule(const char * ifname, unsigned short port, int proto)
{
	rule_t *p;
	struct nftnl_rule *r;
	UNUSED(ifname);

	refresh_nft_cache_filter();
	LIST_FOREACH(p, &head_filter, entry) {
		if (p->dport == port && p->proto == proto && p->type == RULE_FILTER) {
			r = rule_del_handle(p);
			nft_send_rule(r, NFT_MSG_DELRULE, RULE_CHAIN_FILTER);
			break;
		}
	}

	return 0;
}

/*
 * Clear all rules corresponding eport/proto
 */
int
delete_redirect_and_filter_rules(unsigned short eport, int proto)
{
	rule_t *p;
	struct nftnl_rule *r = NULL;
	in_addr_t iaddr = 0;
	uint16_t iport = 0;

	d_printf(("delete_redirect_and_filter_rules(%d %d)\n", eport, proto));
	refresh_nft_cache_redirect();

	// Delete Redirect Rule  eport => iaddr:iport
	LIST_FOREACH(p, &head_redirect, entry) {
		d_printf(("redirect src %08x:%hu dst %08x:%hu nat %08x:%hu proto=%d  type=%d nat_type=%d\n",
		          p->saddr, p->sport, p->daddr, p->dport, p->nat_addr, p->nat_port, p->proto,
		          p->type, p->nat_type));
		if (p->dport == eport && p->proto == proto &&
		    (p->type == RULE_NAT && p->nat_type == NFT_NAT_DNAT)) {
			iaddr = p->nat_addr;
			iport = p->nat_port;
			syslog(LOG_DEBUG, "%s: found redirect rule %hu => %08x:%hu proto %d",
			       "delete_redirect_and_filter_rules", eport, iaddr, iport, proto);

			r = rule_del_handle(p);
			/* Todo: send bulk request */
			if (nft_send_rule(r, NFT_MSG_DELRULE, RULE_CHAIN_REDIRECT) < 0)
				return -1;
			break;
		}
	}

	if (iaddr != 0 && iport != 0) {
		refresh_nft_cache_filter();
		// Delete Forward Rule  on iaddr:iport
		LIST_FOREACH(p, &head_filter, entry) {
			d_printf(("filter   src %08x:%hu dst %08x:%hu nat %08x:%hu proto=%d  type=%d nat_type=%d\n",
			          p->saddr, p->sport, p->daddr, p->dport, p->nat_addr, p->nat_port, p->proto,
			          p->type, p->nat_type));
			if (p->dport == iport && p->daddr == iaddr && p->proto == proto
			    && p->type == RULE_FILTER) {
				syslog(LOG_DEBUG, "%s: found forward/filter rule %08x:%hu proto %d",
				       "delete_redirect_and_filter_rules", iaddr, iport, p->proto);
				r = rule_del_handle(p);
				/* Keep FILTER enforcement if deleting the base rule fails. */
				if (nft_send_rule(r, NFT_MSG_DELRULE, RULE_CHAIN_FILTER) < 0)
					return -1;
				break;
			}
		}
		{
			struct in6_addr address = IN6ADDR_ANY_INIT;
			address.s6_addr[10] = address.s6_addr[11] = 0xff;
			memcpy(address.s6_addr + 12, &iaddr, sizeof(iaddr));
			if (nft_pcp_filter_delete(&address, iport, proto) < 0)
				return -1;
		}
	} else {
		syslog(LOG_WARNING, "%s: redirect rule with eport=%hu proto %d NOT FOUND",
		       "delete_redirect_and_filter_rules", eport, proto);
	}

	return 0;
}

/* Delete only this PEER endpoint, even when other mappings share its NAT port. */
int
delete_peer_rule(const char *iaddr, unsigned short iport,
                 const char *raddr, unsigned short rport, int proto)
{
	rule_t *r;
	refresh_nft_cache_peer();
	LIST_FOREACH(r, &head_peer, entry) {
		if (r->saddr == inet_addr(iaddr) && r->sport == iport &&
		    r->daddr == inet_addr(raddr) && r->dport == rport && r->proto == proto) {
			int ret = nft_send_rule(rule_del_handle(r), NFT_MSG_DELRULE, RULE_CHAIN_PEER);
			if (ret < 0)
				return ret;
			break;
		}
	}
	/* Also discard stale lease state if a rule was removed outside miniupnpd. */
	peer_lease_remove(inet_addr(iaddr), iport, inet_addr(raddr), rport, proto);
	return 0;
}

unsigned int
expire_peer_rules(unsigned int now)
{
	return peer_lease_expire(now, delete_peer_rule, EXPIRE_MAX_PER_PASS);
}

/*
 * get peer by index as array.
 * return -1 when not found.
 */
int
get_peer_rule_by_index(int index,
		       char * ifname, unsigned short * eport,
		       char * iaddr, int iaddrlen, unsigned short * iport,
		       int * proto, char * desc, int desclen,
		       char * rhost, int rhostlen, unsigned short * rport,
		       unsigned int * timestamp,
		       u_int64_t * packets, u_int64_t * bytes)
{
	rule_t *r;
	int i = 0;

	d_printf(("get_peer_rule_by_index()\n"));
	refresh_nft_cache_peer();

	LIST_FOREACH(r, &head_peer, entry) {
		if (i++ == index) {
			if (ifname != NULL) {
				if_indextoname(r->ingress_ifidx, ifname);
			}

			if (eport != NULL) {
				*eport = r->nat_port;
			}

			if (iaddr != NULL) {
				if (inet_ntop(AF_INET, &r->saddr, iaddr, iaddrlen) == NULL) {
					syslog(LOG_ERR, "%s: inet_ntop: %m",
					       "get_peer_rule_by_index");
				}
			}

			if (iport != NULL) {
				*iport = r->sport;
			}

			if (proto != NULL) {
				*proto = r->proto;
			}

			if (rhost != NULL) {
				if (r->daddr) {
					if (inet_ntop(AF_INET, &r->daddr, rhost, rhostlen) == NULL) {
						syslog(LOG_ERR, "%s: inet_ntop: %m",
						       "get_peer_rule_by_index");
					}
				} else {
					rhost[0] = '\0';
				}
			}

			if (rport != NULL) {
				*rport = r->dport;
			}

			if (desc != NULL) {
				strncpy(desc, r->desc, desclen);
			}

			if (packets) {
				*packets = r->packets;
			}
			if (bytes) {
				*bytes = r->bytes;
			}

			if (timestamp) {
				*timestamp = peer_lease_get(r->saddr, r->sport,
				                            r->daddr, r->dport, r->proto);
			}

			return 0;
		}
	}

	return -1;
}

#ifdef PCP_PEER
/*
 * nft_pcp_lease_peers()
 * call cb for each PEER rule, in one pass (for pcp_lease.c)
 */
int
nft_pcp_lease_peers(pcp_lease_peer_cb cb, void * ctx)
{
	rule_t *r;
	uint32_t last_ifidx = 0;
	char last_ifname[IFNAMSIZ] = "";

	refresh_nft_cache_peer();
	LIST_FOREACH(r, &head_peer, entry) {
		struct pcp_lease_peer p;

		memset(&p, 0, sizeof(p));
		if (inet_ntop(AF_INET, &r->saddr, p.iaddr, sizeof(p.iaddr)) == NULL ||
		    inet_ntop(AF_INET, &r->daddr, p.raddr, sizeof(p.raddr)) == NULL)
			continue;
		/* one name lookup per interface, not per rule */
		if (r->ingress_ifidx && r->ingress_ifidx != last_ifidx) {
			if (if_indextoname(r->ingress_ifidx, last_ifname) == NULL)
				last_ifname[0] = '\0';
			last_ifidx = r->ingress_ifidx;
		}
		if (r->ingress_ifidx)
			strncpy(p.ifname, last_ifname, sizeof(p.ifname) - 1);
		p.proto = r->proto;
		p.eport = r->nat_port;
		p.iport = r->sport;
		p.rport = r->dport;
		if (r->desc)
			strncpy(p.desc, r->desc, sizeof(p.desc) - 1);
		p.timestamp = peer_lease_get(r->saddr, r->sport, r->daddr, r->dport, r->proto);
		cb(&p, ctx);
	}
	return 0;
}
#endif /* PCP_PEER */

/*
 * get_redirect_rule()
 * returns -1 if the rule is not found
 */
int
get_redirect_rule(const char * ifname, unsigned short eport, int proto,
		  char * iaddr, int iaddrlen, unsigned short * iport,
		  char * desc, int desclen,
		  char * rhost, int rhostlen,
		  unsigned int * timestamp,
		  u_int64_t * packets, u_int64_t * bytes)
{
	return get_nat_redirect_rule(nft_prerouting_chain,
	                             ifname, eport, proto,
	                             iaddr, iaddrlen, iport,
	                             desc, desclen,
	                             rhost, rhostlen,
	                             timestamp, packets, bytes);
}

/* get_redirect_rule_count()
 * return value : -1 for error or the number of redirection rules */
int
get_redirect_rule_count(const char * ifname)
{
	rule_t *r;
	int n = 0;
	UNUSED(ifname);

	refresh_nft_cache_redirect();
	LIST_FOREACH(r, &head_redirect, entry) {
		n++;
	}
	return n;
}

/*
 * get_redirect_rule_by_index()
 * return -1 when the rule was not found
 */
int
get_redirect_rule_by_index(int index,
			   char * ifname, unsigned short * eport,
			   char * iaddr, int iaddrlen, unsigned short * iport,
			   int * proto, char * desc, int desclen,
			   char * rhost, int rhostlen,
			   unsigned int * timestamp,
			   u_int64_t * packets, u_int64_t * bytes)
{
	rule_t *r;
	int i = 0;

	d_printf(("get_redirect_rule_by_index()\n"));
	refresh_nft_cache_redirect();

	LIST_FOREACH(r, &head_redirect, entry) {
		if (i++ == index) {
			if (ifname != NULL) {
				if_indextoname(r->ingress_ifidx, ifname);
			}

			if (eport != NULL) {
				*eport = r->dport;
			}

			if (iaddr != NULL) {
				if (inet_ntop(AF_INET, &r->nat_addr, iaddr, iaddrlen) == NULL) {
					syslog(LOG_ERR, "%s: inet_ntop: %m",
					       "get_redirect_rule_by_index");
				}
			}

			if (iport != NULL) {
				*iport = r->nat_port;
			}

			if (proto != NULL) {
				*proto = r->proto;
			}

			if (rhost != NULL) {
				if (r->saddr) {
					if (inet_ntop(AF_INET, &r->saddr, rhost, rhostlen) == NULL) {
						syslog(LOG_ERR, "%s: inet_ntop: %m",
						       "get_redirect_rule_by_index");
					}
				} else {
					rhost[0] = '\0';
				}
			}

			if (desc != NULL && r->desc) {
				strncpy(desc, r->desc, desclen);
			}

			if (timestamp != NULL) {
				*timestamp = get_timestamp(*eport, *proto);
			}

			if (packets)
				*packets = r->packets;
			if (bytes)
				*bytes = r->bytes;

			return 0;
		}
	}

	return -1;
}

/*
 * nft_pcp_find_map() : the IPv4 mapping to an internal endpoint
 * (iport 0 : any port). returns 0 if found
 */
int
nft_pcp_find_map(const char * iaddr, unsigned short iport, int proto,
                 unsigned short * eport, char * desc, int desclen,
                 unsigned int * timestamp)
{
	rule_t *r;
	struct in_addr ia;

	if (inet_pton(AF_INET, iaddr, &ia) != 1)
		return -1;
	refresh_nft_cache_redirect();
	LIST_FOREACH(r, &head_redirect, entry) {
		if (r->nat_addr == ia.s_addr && r->proto == proto &&
		    (iport == 0 || r->nat_port == iport)) {
			*eport = r->dport;
			if (desc != NULL && desclen > 0) {
				desc[0] = '\0';
				if (r->desc)
					strncpy(desc, r->desc, desclen - 1);
				desc[desclen - 1] = '\0';
			}
			if (timestamp != NULL)
				*timestamp = get_timestamp(r->dport, proto);
			return 0;
		}
	}
	return -1;
}

/*
 * nft_pcp_find_peer() : a PEER mapping by its two endpoints.
 * returns 0 if found
 */
int
nft_pcp_find_peer(const char * iaddr, unsigned short iport,
                  const char * raddr, unsigned short rport, int proto,
                  unsigned short * eport, char * desc, int desclen,
                  unsigned int * timestamp)
{
	rule_t *r;
	struct in_addr ia, ra;

	if (inet_pton(AF_INET, iaddr, &ia) != 1 ||
	    inet_pton(AF_INET, raddr, &ra) != 1)
		return -1;
	refresh_nft_cache_peer();
	LIST_FOREACH(r, &head_peer, entry) {
		if (r->saddr == ia.s_addr && r->sport == iport &&
		    r->daddr == ra.s_addr && r->dport == rport && r->proto == proto) {
			*eport = r->nat_port;
			if (desc != NULL && desclen > 0) {
				desc[0] = '\0';
				if (r->desc)
					strncpy(desc, r->desc, desclen - 1);
				desc[desclen - 1] = '\0';
			}
			if (timestamp != NULL)
				*timestamp = peer_lease_get(r->saddr, r->sport,
				                            r->daddr, r->dport, r->proto);
			return 0;
		}
	}
	return -1;
}

/* the timestamps of timestamp_list in a hash set on (eport, proto), for a
 * walk over all the rules : get_timestamp() scans the list (and logs) for
 * each rule */
struct timestamp_index {
	const struct timestamp_entry ** tab;	/* NULL : free */
	unsigned int size;			/* a power of 2 */
};

static unsigned int
timestamp_slot(unsigned short eport, int proto, unsigned int size)
{
	return ((eport * 2654435761u) ^ (unsigned int)proto) & (size - 1);
}

/* returns <0 if out of memory */
static int
timestamp_index_build(struct timestamp_index * x)
{
	const struct timestamp_entry * e;
	unsigned int n = 0, i;
	for (e = timestamp_list; e; e = e->next)
		n++;
	x->size = 64;
	while (x->size < 2 * n)
		x->size *= 2;
	x->tab = calloc(x->size, sizeof(*x->tab));
	if (x->tab == NULL)
		return -1;
	for (e = timestamp_list; e; e = e->next) {
		for (i = timestamp_slot(e->eport, e->protocol, x->size); x->tab[i];
		     i = (i + 1) & (x->size - 1)) {
			if (x->tab[i]->eport == e->eport && x->tab[i]->protocol == e->protocol)
				break;	/* the first one in the list wins, as in get_timestamp() */
		}
		if (!x->tab[i])
			x->tab[i] = e;
	}
	return 0;
}

static unsigned int
timestamp_index_get(const struct timestamp_index * x, unsigned short eport, int proto)
{
	unsigned int i;
	for (i = timestamp_slot(eport, proto, x->size); x->tab[i];
	     i = (i + 1) & (x->size - 1)) {
		if (x->tab[i]->eport == eport && x->tab[i]->protocol == (short)proto)
			return x->tab[i]->timestamp;
	}
	return 0;
}

/* Up to max port mappings which expired at 'now'. *next is the next expiry (0
 * if none, 'now' if more mappings have expired than fit in max).
 * returns their number, <0 if out of memory */
int
get_expired_redirect_rules(unsigned int now, struct expired_redirect * expired,
                           int max, unsigned int * next)
{
	rule_t *r;
	struct timestamp_index tx;
	int n = 0;

	*next = 0;
	if (timestamp_index_build(&tx) < 0)
		return -1;
	refresh_nft_cache_redirect();
	LIST_FOREACH(r, &head_redirect, entry) {
		unsigned int ts = timestamp_index_get(&tx, r->dport, r->proto);
		if (ts == 0)
			continue;
		if (ts > now) {
			if (*next == 0 || ts < *next)
				*next = ts;
		} else if (n == max) {
			*next = now;
			break;
		} else {
			expired[n].eport = r->dport;
			expired[n++].proto = r->proto;
		}
	}
	free(tx.tab);
	return n;
}

/*
 * nft_pcp_lease_maps()
 * call cb for each redirect rule (for pcp_lease.c)
 */
int
nft_pcp_lease_maps(pcp_lease_map_cb cb, void * ctx)
{
	rule_t *r;
	struct timestamp_index tx;
	uint32_t last_ifidx = 0;
	char last_ifname[IFNAMSIZ] = "";

	if (timestamp_index_build(&tx) < 0)
		return -1;
	refresh_nft_cache_redirect();
	LIST_FOREACH(r, &head_redirect, entry) {
		struct pcp_lease_map m;

		memset(&m, 0, sizeof(m));
		if (inet_ntop(AF_INET, &r->nat_addr, m.iaddr, sizeof(m.iaddr)) == NULL)
			continue;
		m.proto = r->proto;
		m.eport = r->dport;
		m.iport = r->nat_port;
		if (r->ingress_ifidx && r->ingress_ifidx != last_ifidx) {
			if (if_indextoname(r->ingress_ifidx, last_ifname) == NULL)
				last_ifname[0] = '\0';
			last_ifidx = r->ingress_ifidx;
		}
		if (r->ingress_ifidx)
			strncpy(m.ifname, last_ifname, sizeof(m.ifname) - 1);
		if (r->desc)
			strncpy(m.desc, r->desc, sizeof(m.desc) - 1);
		m.timestamp = timestamp_index_get(&tx, m.eport, m.proto);
		cb(&m, ctx);
	}
	free(tx.tab);
#ifdef ENABLE_UPNPPINHOLE
	nft_pinhole_state_maps(cb, ctx);
#endif
	return 0;
}

/*
 * return -1 not found.
 * return 0 found
 */
int
get_nat_redirect_rule(const char * nat_chain_name, const char * ifname,
		      unsigned short eport, int proto,
		      char * iaddr, int iaddrlen, unsigned short * iport,
		      char * desc, int desclen,
		      char * rhost, int rhostlen,
		      unsigned int * timestamp,
		      u_int64_t * packets, u_int64_t * bytes)
{
	rule_t *p;
	struct in_addr addr;
	UNUSED(nat_chain_name);
	UNUSED(ifname);

	refresh_nft_cache_redirect();

	LIST_FOREACH(p, &head_redirect, entry) {
		if (p->proto == proto &&
		    p->dport == eport) {

			if (rhost != NULL && rhostlen > 0) {
				if (p->saddr) {
					addr.s_addr = p->saddr;
					if (inet_ntop(AF_INET, &addr, rhost, rhostlen) == NULL) {
						syslog(LOG_ERR, "%s: inet_ntop: %m",
						       "get_nat_redirect_rule");
						rhost[0] = '\0';
					}
				} else {
					rhost[0] = '\0';
				}
			}

			if (p->nat_addr && iaddr) {
				addr.s_addr = p->nat_addr;
				if (inet_ntop(AF_INET, &addr, iaddr, iaddrlen) == NULL) {
					syslog(LOG_ERR, "%s: inet_ntop: %m",
					       "get_nat_redirect_rule");
				}
			}

			if (desc != NULL && p->desc) {
				strncpy(desc, p->desc, desclen);
			}

			if (iport)
				*iport = p->nat_port;

			if(timestamp != NULL)
				*timestamp = get_timestamp(eport, proto);

			if(packets)
				*packets = p->packets;
			if(bytes)
				*bytes = p->bytes;

			return 0;
		}
	}

	return -1;
}

/*
 * return an (malloc'ed) array of "external" port for which there is
 * a port mapping. number is the size of the array
 */
unsigned short *
get_portmappings_in_range(unsigned short startport, unsigned short endport,
			  int proto, unsigned int * number)
{
	uint32_t capacity;
	rule_t *p;
	unsigned short *array;
	unsigned short *tmp;

	d_printf(("get_portmappings_in_range()\n"));

	*number = 0;
	capacity = 128;
	array = calloc(capacity, sizeof(unsigned short));

	if (array == NULL) {
		syslog(LOG_ERR, "get_portmappings_in_range(): calloc error");
		return NULL;
	}

	refresh_nft_cache_redirect();

	LIST_FOREACH(p, &head_redirect, entry) {
		if (p->proto == proto &&
		    startport <= p->dport &&
		    p->dport <= endport) {

			if (*number >= capacity) {
				capacity += 128;
				tmp = realloc(array,
					      sizeof(unsigned short)*capacity);
				if (tmp == NULL) {
					syslog(LOG_ERR,
					       "get_portmappings_in_range(): "
					       "realloc(%u) error",
					       (unsigned)sizeof(unsigned short)*capacity);
					*number = 0;
					free(array);
					return NULL;
				}
				array = tmp;
			}
			array[*number] = p->dport;
			(*number)++;
		}
	}
	return array;
}

int
update_portmapping_desc_timestamp(const char * ifname,
                   unsigned short eport, int proto,
                   const char * desc, unsigned int timestamp)
{
	UNUSED(ifname);
	UNUSED(desc);
	remove_timestamp_entry(eport, proto);
	add_timestamp_entry(eport, proto, timestamp);
	return 0;
}

int
update_portmapping(const char * ifname, unsigned short eport, int proto,
                   unsigned short iport, const char * desc,
                   unsigned int timestamp)
{
	char iaddr_str[INET_ADDRSTRLEN];
	char rhost[INET_ADDRSTRLEN];
	int r;

	d_printf(("update_portmapping()\n"));

	iaddr_str[0] = '\0';
	rhost[0] = '\0';
	if (get_redirect_rule(NULL, eport, proto, iaddr_str, INET_ADDRSTRLEN, NULL, NULL, 0, rhost, INET_ADDRSTRLEN, NULL, 0, 0) < 0)
		return -1;

	r = delete_redirect_and_filter_rules(eport, proto);
	if (r < 0)
		return -1;

	if (add_redirect_rule2(ifname, rhost, eport, iaddr_str, iport, proto,
						  desc, timestamp) < 0)
		return -1;

	if (add_filter_rule2(ifname, rhost, iaddr_str, eport, iport, proto, desc) < 0)
		return -1;

	return 0;
}
