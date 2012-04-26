/* $Id: iptpinhole.c,v 1.2 2012/04/26 14:01:17 nanard Exp $ */
/* MiniUPnP project
 * http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * (c) 2012 Thomas Bernard
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <arpa/inet.h>

#include "../config.h"
#include "iptpinhole.h"
#include "../upnpglobalvars.h"

#ifdef ENABLE_6FC_SERVICE

#include <xtables.h>
#include <libiptc/libip6tc.h>
#include "tiny_nf_nat.h"

#define IP6TC_HANDLE struct ip6tc_handle *

static int next_uid = 1;

static struct ip6t_entry_match *
new_match(int proto, unsigned short sport, unsigned short dport)
{
	struct ip6t_entry_match *match;
	struct ip6t_tcp *info;
	size_t size;
	const char * name;
	size =   XT_ALIGN(sizeof(struct ip6t_entry_match))
	       + XT_ALIGN(sizeof(struct ip6t_tcp));
	match = calloc(1, size);
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

	h = ip6tc_init(table);
	if(!h) {
		syslog(LOG_ERR, "ip6tc_init error : %s", ip6tc_strerror(errno));
		return -1;
	}
	if(!ip6tc_is_chain(chain, h)) {
		syslog(LOG_ERR, "chain %s not found", chain);
		goto error;
	}
	if(!ip6tc_append_entry(chain, e, h)) {
		syslog(LOG_ERR, "ip6tc_append_entry() error : %s", ip6tc_strerror(errno));
		goto error;
	}
	if(!ip6tc_commit(h)) {
		syslog(LOG_ERR, "ip6tc_commit() error : %s", ip6tc_strerror(errno));
		goto error;
	}
	return 0;	/* ok */
error:
	ip6tc_free(h);
	return -1;
}

/*
ip6tables -I %s %d -p %s -i %s -s %s --sport %hu -d %s --dport %hu -j ACCEPT
ip6tables -I %s %d -p %s -i %s --sport %hu -d %s --dport %hu -j ACCEPT

miniupnpd_forward_chain, line_number, proto, ext_if_name, raddr, rport, iaddr, iport

ip6tables -t raw -I PREROUTING %d -p %s -i %s -s %s --sport %hu -d %s --dport %hu -j TRACE
ip6tables -t raw -I PREROUTING %d -p %s -i %s --sport %hu -d %s --dport %hu -j TRACE
*/
int add_pinhole(const char * ifname,
                const char * rem_host, unsigned short rem_port,
                const char * int_client, unsigned short int_port,
                int proto)
{
	int uid;
	struct ip6t_entry * e;
	struct ip6t_entry_match *match = NULL;
	struct ip6t_entry_target *target = NULL;

	e = calloc(1, sizeof(struct ip6t_entry));
	e->ipv6.proto = proto;

	if(ifname)
		strncpy(e->ipv6.iniface, ifname, IFNAMSIZ);
	if(rem_host) {
		inet_pton(AF_INET6, rem_host, &e->ipv6.src);
		memset(&e->ipv6.smsk, 0xff, sizeof(e->ipv6.smsk));
	}
	inet_pton(AF_INET6, int_client, &e->ipv6.dst);
	memset(&e->ipv6.dmsk, 0xff, sizeof(e->ipv6.dmsk));

	/*e->nfcache = NFC_IP_DST_PT;*/
	/*e->nfcache |= NFC_UNKNOWN;*/

	match = new_match(proto, rem_port, int_port);
	target = get_accept_target();
	e = realloc(e, sizeof(struct ip6t_entry)
	               + match->u.match_size
	               + target->u.target_size);
	memcpy(e->elems, match, match->u.match_size);
	memcpy(e->elems + match->u.match_size, target, target->u.target_size);
	e->target_offset = sizeof(struct ip6t_entry)
	                   + match->u.match_size;
	e->next_offset = sizeof(struct ip6t_entry)
	                 + match->u.match_size
					 + target->u.target_size;
	free(match);
	free(target);

	if(ip6tc_init_verify_append("filter", miniupnpd_v6_filter_chain, e) < 0) {
		free(e);
		return -1;
	}
	free(e);
	uid = next_uid;
	next_uid++;
	return uid;
}

#endif

