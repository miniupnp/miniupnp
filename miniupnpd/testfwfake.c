/* MiniUPnP project
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

/* The fake firewall of the unit tests, see testfwfake.h. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "commonrdr.h"
#include "testfwfake.h"

int fail_add_redirect;	/* add_redirect_rule2() call number N fails */
int redirect_calls;
int fail_add_filter;	/* add_filter_rule2() fails */
int fail_delete;		/* the deletes fail */
int rule_present;	/* get_redirect_rule(): 1 the rule, 0 none, -1 an error */
const char * rule_iaddr = "192.168.1.10";	/* the target of that rule */
unsigned short rule_iport = 5000;
int adds, deletes, updates;
unsigned short last_update_iport;
int rules_listed = -1;	/* get_redirect_rule_by_index(): -1 FAKE_RULES */

int
add_redirect_rule2(const char * ifname, const char * rhost, unsigned short eport,
                   const char * iaddr, unsigned short iport, int proto,
                   const char * desc, unsigned int timestamp)
{
	(void)ifname; (void)rhost; (void)eport; (void)iaddr; (void)iport;
	(void)proto; (void)desc; (void)timestamp;
	if(++redirect_calls == fail_add_redirect)
		return -1;
	adds++;
	return 0;
}

int
add_filter_rule2(const char * ifname, const char * rhost, const char * iaddr,
                 unsigned short eport, unsigned short iport, int proto,
                 const char * desc)
{
	(void)ifname; (void)rhost; (void)iaddr; (void)eport; (void)iport;
	(void)proto; (void)desc;
	return fail_add_filter ? -1 : 0;
}

static int
fake_delete(void)
{
	if(fail_delete)
		return -1;
	deletes++;
	if(rules_listed > 0)
		rules_listed--;	/* the first rule listed went */
#if defined(PCP_PEER) && defined(USE_NETFILTER)
	else if(rules_listed == 0)
		peer_present = 0;	/* the PEER rule went, by its port */
#endif
	return 0;
}

#if defined(__linux__)
int
delete_redirect_and_filter_rules(unsigned short eport, int proto)
{
	(void)eport; (void)proto;
	return fake_delete();
}
#else
#if defined(USE_PF)
int
delete_redirect_and_filter_rules(const char * ifname, unsigned short eport, int proto)
{
	(void)ifname; (void)eport; (void)proto;
	return fake_delete();
}
#else
int
delete_filter_rule(const char * ifname, unsigned short eport, int proto)
{
	(void)ifname; (void)eport; (void)proto;
	return 0;
}
#endif
#endif

int
delete_redirect_rule(const char * ifname, unsigned short eport, int proto)
{
	(void)ifname; (void)eport; (void)proto;
	return fake_delete();
}

int
get_redirect_rule(const char * ifname, unsigned short eport, int proto,
                  char * iaddr, int iaddrlen, unsigned short * iport,
                  char * desc, int desclen, char * rhost, int rhostlen,
                  unsigned int * timestamp, u_int64_t * packets, u_int64_t * bytes)
{
	(void)ifname; (void)eport; (void)proto;
	(void)timestamp; (void)packets; (void)bytes;
	if(rule_present <= 0)
		return rule_present == 0 ? -2 : -1;
	if(iaddr != NULL && iaddrlen > 0)
		snprintf(iaddr, (size_t)iaddrlen, "%s", rule_iaddr);
	if(iport != NULL)
		*iport = rule_iport;
	if(desc != NULL && desclen > 0)
		desc[0] = '\0';
	if(rhost != NULL && rhostlen > 0)
		rhost[0] = '\0';
	return 0;
}

#if defined(USE_IPTABLES)
int
get_redirect_rules_counters(void (*fn)(unsigned short eport, int proto,
                                       u_int64_t packets, u_int64_t bytes, void * arg),
                            void * arg)
{
	int i;
	for(i = 0; i < FAKE_RULES; i++)
		fn((unsigned short)(5000 + i), IPPROTO_TCP, (u_int64_t)(10 * i), (u_int64_t)(100 * i), arg);
	return 0;
}
#endif

int
get_redirect_rule_by_index(int index, char * ifname, unsigned short * eport,
                           char * iaddr, int iaddrlen, unsigned short * iport,
                           int * proto, char * desc, int desclen,
                           char * rhost, int rhostlen, unsigned int * timestamp,
                           u_int64_t * packets, u_int64_t * bytes)
{
	(void)ifname; (void)desc; (void)desclen; (void)timestamp;
	if(index >= (rules_listed >= 0 ? rules_listed : FAKE_RULES))
		return -1;
	*eport = (unsigned short)(5000 + index);
	*iport = *eport;
	if(iaddr != NULL && iaddrlen > 0)
		snprintf(iaddr, (size_t)iaddrlen, "%s", rule_iaddr);
	if(rhost != NULL && rhostlen > 0)
		rhost[0] = '\0';
	*proto = IPPROTO_TCP;
	*packets = (u_int64_t)(10 * index);
	*bytes = (u_int64_t)(100 * index);
	return 0;
}

int
update_portmapping(const char * ifname, unsigned short eport, int proto,
                   unsigned short iport, const char * desc, unsigned int timestamp)
{
	(void)ifname; (void)eport; (void)proto; (void)desc; (void)timestamp;
	updates++;
	last_update_iport = iport;
	return 0;
}

int
update_portmapping_desc_timestamp(const char * ifname, unsigned short eport, int proto,
                                  const char * desc, unsigned int timestamp)
{
	(void)ifname; (void)eport; (void)proto; (void)desc; (void)timestamp;
	updates++;
	return 0;
}

#if defined(PCP_PEER) && defined(USE_NETFILTER)
int peer_adds, fail_peer_add;
int peer_present;	/* get_peer_rule_by_index() lists the PEER rule */

int
add_peer_redirect_rule2(const char * ifname, const char * rhost, unsigned short rport,
                        const char * eaddr, unsigned short eport,
                        const char * iaddr, unsigned short iport, int proto,
                        const char * desc, unsigned int timestamp)
{
	(void)ifname; (void)rhost; (void)rport; (void)eaddr; (void)eport;
	(void)iaddr; (void)iport; (void)proto; (void)desc; (void)timestamp;
	if(peer_adds + 1 == fail_peer_add)
		return -1;
	peer_adds++;
	return 0;
}

/* the PEER rule of each key goes, or is not there (peer_present 0) */
int
outgoing_rule_delete(struct outgoing_rule_key * keys, int n)
{
	int i;

	if(fail_delete)
		return -1;
	for(i = 0; i < n; i++) {
		keys[i].result = peer_present ? 0 : -2;
		if(peer_present)
			deletes++;
	}
	peer_present = 0;
	return 0;
}

int
add_peer_dscp_rule2(const char * ifname, const char * rhost, unsigned short rport,
                    unsigned char dscp, const char * iaddr, unsigned short iport,
                    int proto, const char * desc, unsigned int timestamp)
{
	(void)ifname; (void)rhost; (void)rport; (void)dscp; (void)iaddr;
	(void)iport; (void)proto; (void)desc; (void)timestamp;
	return 0;
}

int
get_peer_rule_by_index(int index, char * ifname, unsigned short * eport,
                       char * iaddr, int iaddrlen, unsigned short * iport,
                       int * proto, char * desc, int desclen,
                       char * rhost, int rhostlen, unsigned short * rport,
                       unsigned int * timestamp, u_int64_t * packets, u_int64_t * bytes)
{
	(void)ifname; (void)desc; (void)desclen;
	(void)timestamp; (void)packets; (void)bytes;
	if(index > 0 || !peer_present)
		return -1;
	if(iaddr != NULL && iaddrlen > 0)
		snprintf(iaddr, (size_t)iaddrlen, "%s", rule_iaddr);
	if(rhost != NULL && rhostlen > 0)
		snprintf(rhost, (size_t)rhostlen, "203.0.113.7");
	*eport = 6000;
	*iport = 5000;
	*proto = IPPROTO_UDP;
	*rport = 7000;
	return 0;
}
#endif

#ifdef FW_MAP6
int map6_adds, map6_deletes, fail_map6_add_at, map6_gone;
int map6_lost;	/* get_map6_packets() finds no rule */
int map6_listed;	/* get_map6_rule_at() lists this many rules */

int
add_map6_rule(const char * ifname, const char * rem_host, unsigned short rem_port,
              const char * int_client, unsigned short int_port,
              int proto, const char * desc, unsigned int timestamp)
{
	(void)ifname; (void)rem_host; (void)rem_port; (void)int_client;
	(void)int_port; (void)proto; (void)desc; (void)timestamp;
	if(map6_adds + 1 == fail_map6_add_at)
		return -1;
	map6_adds++;
	return 0;
}

/* the first map6_gone deletes find no rule (-2) */
int
delete_map6_rule(const char * rem_host, unsigned short rem_port,
                 const char * int_client, unsigned short int_port, int proto)
{
	(void)rem_host; (void)rem_port; (void)int_client; (void)int_port; (void)proto;
	if(map6_gone > 0) {
		map6_gone--;
		return -2;
	}
	if(fail_delete)
		return -1;
	map6_deletes++;
	if(map6_listed > 0)
		map6_listed--;	/* the first rule listed went */
	return 0;
}

int
get_map6_packets(const char * rem_host, unsigned short rem_port,
                 const char * int_client, unsigned short int_port,
                 int proto, u_int64_t * packets)
{
	(void)rem_host; (void)rem_port; (void)int_client; (void)int_port; (void)proto;
	*packets = 0;
	return map6_lost ? -2 : 0;
}

/* [2001:db8::10]:6000 + index from any remote */
int
get_map6_rule_at(int index, char * rem_host, int rem_hostlen,
                 unsigned short * rem_port,
                 char * int_client, int int_clientlen,
                 unsigned short * int_port, int * proto,
                 char * desc, int desclen)
{
	(void)desc; (void)desclen;
	if(index >= map6_listed)
		return -1;
	if(rem_host != NULL && rem_hostlen > 0)
		rem_host[0] = '\0';
	*rem_port = 0;
	snprintf(int_client, (size_t)int_clientlen, "2001:db8::10");
	*int_port = (unsigned short)(6000 + index);
	*proto = IPPROTO_TCP;
	return 0;
}
#endif

void
reset(void)
{
	fail_add_redirect = 0;
	redirect_calls = 0;
	fail_add_filter = 0;
	fail_delete = 0;
	rule_present = 1;
	rule_iaddr = "192.168.1.10";
	rule_iport = 5000;
	adds = deletes = updates = 0;
	last_update_iport = 0;
	rules_listed = -1;
#ifdef FW_MAP6
	map6_adds = map6_deletes = fail_map6_add_at = map6_gone = map6_lost = 0;
	map6_listed = 0;
#endif
#if defined(PCP_PEER) && defined(USE_NETFILTER)
	peer_adds = 0;
	fail_peer_add = 0;
	peer_present = 1;
#endif
}

