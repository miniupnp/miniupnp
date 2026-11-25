/* $Id: iptpinhole.c,v 1.24 2025/01/25 21:18:16 nanard Exp $ */
/* MiniUPnP project
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * (c) 2012-2025 Thomas Bernard
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <arpa/inet.h>

#include "config.h"
#include "../macros.h"
#include "iptpinhole.h"
#include "../upnpglobalvars.h"
#include "../upnputils.h"

#ifdef ENABLE_UPNPPINHOLE

#include <xtables.h>
#include <libiptc/libip6tc.h>
#include "tiny_nf_nat.h"

#define IP6TC_HANDLE struct ip6tc_handle *

static const char * miniupnpd_v6_filter_chain = "MINIUPNPD";

/* the rules of the chain are the record: nothing is kept in memory */
void init_iptpinhole(void)
{
	return;
}

void shutdown_iptpinhole(void)
{
	return;
}

/* new_match()
 * Allocate and set a new ip6t_entry_match structure
 * The caller must free() it after usage */
static struct ip6t_entry_match *
new_match(int proto, unsigned short sport, unsigned short dport)
{
	struct ip6t_entry_match *match;
	struct ip6t_tcp *info;	/* TODO : use ip6t_udp if needed */
	size_t size;
	const char * name;
	size =   XT_ALIGN(sizeof(struct ip6t_entry_match))
	       + XT_ALIGN(sizeof(struct ip6t_tcp));
	match = calloc(1, size);
	if(!match) {
		syslog(LOG_ERR, "%s: calloc(%d) error", "new_match", (int)size);
		return NULL;
	}
	match->u.user.match_size = size;
	switch(proto) {
	case IPPROTO_TCP:
		name = "tcp";
		break;
	case IPPROTO_UDP:
		name = "udp";
		break;
	case IPPROTO_UDPLITE:
		name = "udplite";
		break;
	default:
		name = NULL;
	}
	if(name)
		strncpy(match->u.user.name, name, sizeof(match->u.user.name));
	else
		syslog(LOG_WARNING, "no name for protocol %d", proto);
	info = (struct ip6t_tcp *)match->data;
	if(sport) {
		info->spts[0] = sport;	/* specified source port */
		info->spts[1] = sport;
	} else {
		info->spts[0] = 0;		/* all source ports */
		info->spts[1] = 0xFFFF;
	}
	info->dpts[0] = dport;	/* specified destination port */
	info->dpts[1] = dport;
	return match;
}

static struct ip6t_entry_target *
get_accept_target(void)
{
	struct ip6t_entry_target * target = NULL;
	size_t size;
	size =   XT_ALIGN(sizeof(struct ip6t_entry_target))
	       + XT_ALIGN(sizeof(int));
	target = calloc(1, size);
	if(!target) {
		syslog(LOG_ERR, "%s: calloc(%d) error", "get_accept_target", (int)size);
		return NULL;
	}
	target->u.user.target_size = size;
	strncpy(target->u.user.name, "ACCEPT", sizeof(target->u.user.name));
	return target;
}

static int
ip6tc_init_verify_append(const char * table,
                         const char * chain,
                         struct ip6t_entry * e)
{
	IP6TC_HANDLE h;
	xt_chainlabel chainlabel;

	h = ip6tc_init(table);
	if(!h) {
		syslog(LOG_ERR, "ip6tc_init error : %s", ip6tc_strerror(errno));
		return -1;
	}
	strncpy(chainlabel, chain, sizeof(chainlabel));
	if(!ip6tc_is_chain(chainlabel, h)) {
		syslog(LOG_ERR, "chain %s not found", chain);
		goto error;
	}
	if(!ip6tc_append_entry(chainlabel, e, h)) {
		syslog(LOG_ERR, "ip6tc_append_entry() error : %s", ip6tc_strerror(errno));
		goto error;
	}
	if(!ip6tc_commit(h)) {
		syslog(LOG_ERR, "ip6tc_commit() error : %s", ip6tc_strerror(errno));
		goto error;
	}
	ip6tc_free(h);
	return 0;	/* ok */
error:
	ip6tc_free(h);
	return -1;
}

/* The key of a map6 rule, as the rule holds it: no remote host is the
 * address :: and no remote port is 0. 0, or -2 if an address does not parse */
static int
rule_key(const char * rem_host, const char * int_client,
         struct in6_addr * saddr, struct in6_addr * daddr)
{
	memset(saddr, 0, sizeof(*saddr));
	if(!map6_any_remote(rem_host) && inet_pton(AF_INET6, rem_host, saddr) < 1) {
		syslog(LOG_WARNING, "failed to parse INET6 address \"%s\"", rem_host);
		return -2;
	}
	if(inet_pton(AF_INET6, int_client, daddr) < 1) {
		syslog(LOG_WARNING, "failed to parse INET6 address \"%s\"", int_client);
		return -2;
	}
	return 0;
}

/* The rule of the key in the chain of h, and its index in *index. NULL if
 * there is none */
static const struct ip6t_entry *
find_rule(IP6TC_HANDLE h, const struct in6_addr * saddr, unsigned short sport,
          const struct in6_addr * daddr, unsigned short dport, int proto,
          unsigned int * index)
{
	const struct ip6t_entry * e;
	const struct ip6t_entry_match * match;
	const struct ip6t_tcp * info;
	unsigned int i = 0;

	for(e = ip6tc_first_rule(miniupnpd_v6_filter_chain, h);
	    e;
	    e = ip6tc_next_rule(e, h), i++) {
		if((e->ipv6.proto != proto) ||
		   (0 != memcmp(&e->ipv6.src, saddr, sizeof(e->ipv6.src))) ||
		   (0 != memcmp(&e->ipv6.dst, daddr, sizeof(e->ipv6.dst))))
			continue;
		match = (const struct ip6t_entry_match *)&e->elems;
		info = (const struct ip6t_tcp *)&match->data;
		if((info->spts[0] == sport) && (info->dpts[0] == dport)) {
			if(index)
				*index = i;
			return e;
		}
	}
	return NULL;
}

/* the filter table, with the chain of the daemon. NULL on an error */
static IP6TC_HANDLE
init_filter(void)
{
	IP6TC_HANDLE h;

	h = ip6tc_init("filter");
	if(!h) {
		syslog(LOG_ERR, "ip6tc_init error : %s", ip6tc_strerror(errno));
		return NULL;
	}
	if(!ip6tc_is_chain(miniupnpd_v6_filter_chain, h)) {
		syslog(LOG_ERR, "chain %s not found", miniupnpd_v6_filter_chain);
		ip6tc_free(h);
		return NULL;
	}
	return h;
}

/*
ip6tables -I %s %d -p %s -i %s -s %s --sport %hu -d %s --dport %hu -j ACCEPT
ip6tables -I %s %d -p %s -i %s --sport %hu -d %s --dport %hu -j ACCEPT
*/
int
add_map6_rule(const char * ifname,
              const char * rem_host, unsigned short rem_port,
              const char * int_client, unsigned short int_port,
              int proto, const char * desc, unsigned int timestamp)
{
	struct ip6t_entry * e;
	struct ip6t_entry * tmp;
	struct ip6t_entry_match *match = NULL;
	struct ip6t_entry_target *target = NULL;
	int r;

	UNUSED(desc); UNUSED(timestamp);	/* the lease table has them */
	e = calloc(1, sizeof(struct ip6t_entry));
	if(!e) {
		syslog(LOG_ERR, "%s: calloc(%d) failed",
		       "add_map6_rule", (int)sizeof(struct ip6t_entry));
		return -1;
	}
	if(rule_key(rem_host, int_client, &e->ipv6.src, &e->ipv6.dst) < 0) {
		free(e);
		return -1;
	}
	if(!map6_any_remote(rem_host))
		memset(&e->ipv6.smsk, 0xff, sizeof(e->ipv6.smsk));
	memset(&e->ipv6.dmsk, 0xff, sizeof(e->ipv6.dmsk));
	e->ipv6.proto = proto;
	if (proto)
		e->ipv6.flags |= IP6T_F_PROTO;

	/* TODO: check if enforcing USE_IFNAME_IN_RULES is needed */
	if(ifname)
		strncpy(e->ipv6.iniface, ifname, IFNAMSIZ);

	match = new_match(proto, rem_port, int_port);
	target = get_accept_target();
	if(!match || !target) {
		syslog(LOG_ERR, "%s: failed to build match/target", "add_map6_rule");
		free(match);
		free(target);
		free(e);
		return -1;
	}
	tmp = realloc(e, sizeof(struct ip6t_entry)
	               + match->u.match_size
	               + target->u.target_size);
	if(!tmp) {
		syslog(LOG_ERR, "%s: realloc(%d) failed",
		       "add_map6_rule", (int)(sizeof(struct ip6t_entry) + match->u.match_size + target->u.target_size));
		free(e);
		free(match);
		free(target);
		return -1;
	}
	e = tmp;
	memcpy(e->elems, match, match->u.match_size);
	memcpy(e->elems + match->u.match_size, target, target->u.target_size);
	e->target_offset = sizeof(struct ip6t_entry)
	                   + match->u.match_size;
	e->next_offset = sizeof(struct ip6t_entry)
	                 + match->u.match_size
					 + target->u.target_size;
	free(match);
	free(target);

	r = ip6tc_init_verify_append("filter", miniupnpd_v6_filter_chain, e);
	free(e);
	return r < 0 ? -1 : 0;
}

int
delete_map6_rule(const char * rem_host, unsigned short rem_port,
                 const char * int_client, unsigned short int_port, int proto)
{
	IP6TC_HANDLE h;
	struct in6_addr saddr, daddr;
	unsigned int index;

	if(rule_key(rem_host, int_client, &saddr, &daddr) < 0)
		return -2;
	h = init_filter();
	if(!h)
		return -1;
	if(!find_rule(h, &saddr, rem_port, &daddr, int_port, proto, &index)) {
		ip6tc_free(h);
		return -2;	/* not found */
	}
	if(!ip6tc_delete_num_entry(miniupnpd_v6_filter_chain, index, h)) {
		syslog(LOG_ERR, "ip6tc_delete_num_entry(%s,%u,...): %s",
		       miniupnpd_v6_filter_chain, index, ip6tc_strerror(errno));
		ip6tc_free(h);
		return -1;
	}
	if(!ip6tc_commit(h)) {
		syslog(LOG_ERR, "ip6tc_commit(): %s", ip6tc_strerror(errno));
		ip6tc_free(h);
		return -1;
	}
	ip6tc_free(h);
	return 0;
}

int
get_map6_packets(const char * rem_host, unsigned short rem_port,
                 const char * int_client, unsigned short int_port,
                 int proto, u_int64_t * packets)
{
	IP6TC_HANDLE h;
	const struct ip6t_entry * e;
	struct in6_addr saddr, daddr;

	if(rule_key(rem_host, int_client, &saddr, &daddr) < 0)
		return -2;
	h = init_filter();
	if(!h)
		return -1;
	e = find_rule(h, &saddr, rem_port, &daddr, int_port, proto, NULL);
	if(e && packets)
		*packets = e->counters.pcnt;
	ip6tc_free(h);
	return e ? 0 : -2;
}

int
get_map6_rule_at(int index, char * rem_host, int rem_hostlen,
                    unsigned short * rem_port,
                    char * int_client, int int_clientlen,
                    unsigned short * int_port, int * proto,
                    char * desc, int desclen)
{
	IP6TC_HANDLE h;
	const struct ip6t_entry * e;
	const struct ip6t_entry_match * match;
	const struct ip6t_tcp * info;
	int r = -1;

	h = init_filter();
	if(!h)
		return -1;
	for(e = ip6tc_first_rule(miniupnpd_v6_filter_chain, h);
	    e;
	    e = ip6tc_next_rule(e, h)) {
		/* a map6 rule matches a protocol and its ports */
		if(e->ipv6.proto == 0 || e->target_offset <= sizeof(struct ip6t_entry))
			continue;
		if(index-- > 0)
			continue;
		match = (const struct ip6t_entry_match *)&e->elems;
		info = (const struct ip6t_tcp *)&match->data;
		if(rem_host && rem_hostlen > 0) {
			if(IN6_IS_ADDR_UNSPECIFIED(&e->ipv6.src))
				rem_host[0] = '\0';
			else if(inet_ntop(AF_INET6, &e->ipv6.src, rem_host, rem_hostlen) == NULL)
				break;
		}
		if(int_client &&
		   inet_ntop(AF_INET6, &e->ipv6.dst, int_client, int_clientlen) == NULL)
			break;
		if(rem_port)
			*rem_port = info->spts[0];
		if(int_port)
			*int_port = info->dpts[0];
		if(proto)
			*proto = e->ipv6.proto;
		if(desc && desclen > 0)
			desc[0] = '\0';	/* the rule holds none */
		r = 0;
		break;
	}
	ip6tc_free(h);
	return r;
}

#endif /* ENABLE_UPNPPINHOLE */
