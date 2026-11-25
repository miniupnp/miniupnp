/* vim: tabstop=4 shiftwidth=4 noexpandtab
 * MiniUPnP project
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

/* Stubs for the firewall, network-interface and event back-ends, so the
 * HTTP/SOAP and PCP/NAT-PMP code can be fuzzed in-process. They return a
 * small fixed table of port mappings and pinholes, so the code that builds
 * replies from existing rules is exercised too. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "config.h"
#include "upnpglobalvars.h"
#include "getifstats.h"
#include "upnppermissions.h"

static struct lan_addr_s lan;
unsigned int fuzz_num_perm;	/* number of permission rules loaded by fuzz_init() */

void fuzz_init(void)
{
	ext_if_name = "eth1";
	runtime_flags = ENABLEUPNPMASK | SECUREMODEMASK | ALLOWPRIVATEIPV4MASK;
	LIST_INIT(&lan_addrs);
	strcpy(lan.ifname, "eth0");
	strcpy(lan.str, "192.168.1.1");
	inet_pton(AF_INET, "192.168.1.1", &lan.addr);
	inet_pton(AF_INET, "255.255.255.0", &lan.mask);
	LIST_INSERT_HEAD(&lan_addrs, &lan, list);
	/* typical permission rules (miniupnpd.conf), so the permission checks run */
	{
		static const char * rules[] = {
			"allow 1024-65535 192.168.1.0/24 1024-65535",
			"allow 80 192.168.1.100/32 80",
			"deny 0-1023 0.0.0.0/0 0-65535",
		};
		static struct upnpperm perms[3];
		char line[128];
		unsigned int i;
		for(i = 0; i < sizeof(rules)/sizeof(rules[0]); i++) {
			strcpy(line, rules[i]);	/* read_permission_line() modifies its input */
			if(read_permission_line(perms + num_upnpperm, line) >= 0)
				num_upnpperm++;
		}
		upnppermlist = perms;
		fuzz_num_perm = num_upnpperm;
	}
}


int addr_is_reserved(struct in_addr *a) { (void)a; return 0; }
int get_src_for_route_to(const struct sockaddr *d, void *s, size_t *l, int *i) { (void)d; (void)s; (void)l; (void)i; return -1; }
int get_wan_connection_status(const char *n) { (void)n; return 2; }
const char *get_wan_connection_status_str(const char *n) { (void)n; return "Connected"; }
int getifaddr(const char *n, char *buf, int len, struct in_addr *addr, struct in_addr *mask)
{
	(void)n;
	snprintf(buf, len, "%s", "203.0.113.7");
	if (addr) inet_pton(AF_INET, "203.0.113.7", addr);
	if (mask) inet_pton(AF_INET, "255.255.255.0", mask);
	return 0;
}
int getifstats(const char *n, struct ifdata *d) { (void)n; memset(d, 0, sizeof(*d)); d->baudrate = 1000000000; d->opackets = 12345; d->ipackets = 54321; d->obytes = 1ULL<<33; d->ibytes = 1ULL<<34; return 0; }

static const struct { unsigned short eport, iport; const char *proto, *iaddr, *desc, *rhost; unsigned lease; } T[] = {
	{8080, 80, "TCP", "192.168.1.100", "web <server> & \"x\"", "", 0},
	{5000, 5000, "UDP", "192.168.1.101", "PCP 0123456789abcdef0123456789", "198.51.100.1", 3600},
	{443, 443, "TCP", "192.168.1.100", "", "", 86400},
};
#define NT (int)(sizeof(T)/sizeof(T[0]))

int upnp_redirect(const char *rh, unsigned short ep, const char *ia, unsigned short ip, const char *pr, const char *de, unsigned int ld)
{ (void)rh; (void)ia; (void)ip; (void)pr; (void)de; (void)ld; return ep == 8080 ? -2 : 0; }
int upnp_delete_redirection(unsigned short ep, const char *pr) { (void)pr; return ep == 8080 ? 0 : -1; }
int upnp_get_portmapping_number_of_entries(void) { return NT; }

static int fill(int k, unsigned short *iport, char *iaddr, int iaddrlen, char *desc, int desclen, char *rhost, int rhostlen, unsigned int *ld)
{
	if (iport) *iport = T[k].iport;
	if (iaddr) snprintf(iaddr, iaddrlen, "%s", T[k].iaddr);
	if (desc) snprintf(desc, desclen, "%s", T[k].desc);
	if (rhost) snprintf(rhost, rhostlen, "%s", T[k].rhost);
	if (ld) *ld = T[k].lease;
	return 0;
}
int upnp_get_redirection_infos(unsigned short ep, const char *pr, unsigned short *iport, char *iaddr, int iaddrlen,
                               char *desc, int desclen, char *rhost, int rhostlen, unsigned int *ld)
{
	for (int k = 0; k < NT; k++)
		if (T[k].eport == ep && pr && strcmp(pr, T[k].proto) == 0)
			return fill(k, iport, iaddr, iaddrlen, desc, desclen, rhost, rhostlen, ld);
	return -1;
}
int upnp_get_redirection_infos_by_index(int idx, unsigned short *ep, char *pr, unsigned short *iport, char *iaddr, int iaddrlen,
                                        char *desc, int desclen, char *rhost, int rhostlen, unsigned int *ld)
{
	if (idx < 0 || idx >= NT) return -1;
	if (ep) *ep = T[idx].eport;
	if (pr) memcpy(pr, T[idx].proto, 4);
	return fill(idx, iport, iaddr, iaddrlen, desc, desclen, rhost, rhostlen, ld);
}
unsigned short *upnp_get_portmappings_in_range(unsigned short s, unsigned short e, const char *pr, unsigned int *n)
{
	unsigned short *a = malloc(NT * sizeof(*a));
	*n = 0;
	if (!a) return NULL;
	for (int k = 0; k < NT; k++)
		if (T[k].eport >= s && T[k].eport <= e && pr && strcmp(pr, T[k].proto) == 0) a[(*n)++] = T[k].eport;
	return a;
}

int upnp_add_inboundpinhole(const char *ra, unsigned short rp, const char *ia, unsigned short ip, int pr, char *de, unsigned int lt, int *uid)
{ (void)ra; (void)rp; (void)ia; (void)ip; (void)pr; (void)de; (void)lt; *uid = 7; return 1; }
int upnp_update_inboundpinhole(unsigned short uid, unsigned int lt) { (void)lt; return uid == 7 ? 0 : -1; }
int upnp_delete_inboundpinhole(unsigned short uid) { return uid == 7 ? 0 : -1; }
int upnp_get_pinhole_info(unsigned short uid, char *ra, int ral, unsigned short *rp, char *ia, int ial, unsigned short *ip,
                          int *pr, char *de, int del, unsigned int *lt, unsigned int *pk)
{
	if (uid != 7) return -2;
	if (ra) snprintf(ra, ral, "2001:db8::1"); if (rp) *rp = 1234;
	if (ia) snprintf(ia, ial, "2001:db8::100"); if (ip) *ip = 22;
	if (pr) *pr = 6; if (de) snprintf(de, del, "pinhole"); if (lt) *lt = 3600; if (pk) *pk = 10;
	return 0;
}

const char *upnpevents_addSubscriber(const char *u, const char *cb, int cbl, int to) { (void)u; (void)cb; (void)cbl; (void)to; return "uuid:11111111-2222-3333-4444-555555555555"; }
int upnpevents_removeSubscriber(const char *sid, int l) { (void)sid; return l > 5 ? 0 : -1; }
const char *upnpevents_renewSubscription(const char *sid, int l, int to) { (void)to; return (sid && l > 5) ? "uuid:11111111-2222-3333-4444-555555555555" : NULL; }

/* PCP / NAT-PMP back-end */
static int fill_rule(char *iaddr, int iaddrlen, unsigned short *iport, char *desc, int desclen,
                     char *rhost, int rhostlen, unsigned int *ts, u_int64_t *pk, u_int64_t *by)
{
	if (iaddr) snprintf(iaddr, iaddrlen, "192.168.1.100");
	if (iport) *iport = 80;
	if (desc) snprintf(desc, desclen, "PCP MAP 0123456789abcdef01234567");
	if (rhost) snprintf(rhost, rhostlen, "%s", "");
	if (ts) *ts = 0; if (pk) *pk = 1; if (by) *by = 100;
	return 0;
}
int get_redirect_rule(const char *ifn, unsigned short eport, int proto, char *iaddr, int iaddrlen, unsigned short *iport,
                      char *desc, int desclen, char *rhost, int rhostlen, unsigned int *ts, u_int64_t *pk, u_int64_t *by)
{
	(void)ifn; (void)proto;
	if (eport != 8080) return -1;
	return fill_rule(iaddr, iaddrlen, iport, desc, desclen, rhost, rhostlen, ts, pk, by);
}
int get_redirect_rule_by_index(int index, char *ifname, unsigned short *eport, char *iaddr, int iaddrlen, unsigned short *iport,
                               int *proto, char *desc, int desclen, char *rhost, int rhostlen, unsigned int *ts, u_int64_t *pk, u_int64_t *by)
{
	if (index != 0) return -1;
	if (ifname) strcpy(ifname, "eth1");
	if (eport) *eport = 8080; if (proto) *proto = IPPROTO_TCP;
	return fill_rule(iaddr, iaddrlen, iport, desc, desclen, rhost, rhostlen, ts, pk, by);
}
int get_peer_rule_by_index(int index, char *ifname, unsigned short *eport, char *iaddr, int iaddrlen, unsigned short *iport,
                           int *proto, char *desc, int desclen, char *rhost, int rhostlen, unsigned short *rport,
                           unsigned int *ts, u_int64_t *pk, u_int64_t *by)
{
	if (index != 0) return -1;
	if (ifname) strcpy(ifname, "eth1");
	if (eport) *eport = 9000; if (proto) *proto = IPPROTO_UDP; if (rport) *rport = 1234;
	fill_rule(iaddr, iaddrlen, iport, desc, desclen, rhost, rhostlen, ts, pk, by);
	if (rhost) snprintf(rhost, rhostlen, "198.51.100.1");
	return 0;
}
int _upnp_delete_redir(unsigned short eport, int proto) { (void)proto; return eport == 8080 ? 0 : -1; }
int add_peer_redirect_rule2(const char *ifn, const char *rh, unsigned short rp, const char *ea, unsigned short ep,
                            const char *ia, unsigned short ip, int pr, const char *de, unsigned int ts)
{ (void)ifn; (void)rh; (void)rp; (void)ea; (void)ep; (void)ia; (void)ip; (void)pr; (void)de; (void)ts; return 0; }
int upnp_redirect_internal(const char *rh, unsigned short ep, const char *ia, unsigned short ip, int pr, const char *de, unsigned int ts)
{ (void)rh; (void)ia; (void)ip; (void)pr; (void)de; (void)ts; return ep == 8080 ? -1 : 0; }
int get_nat_ext_addr(struct sockaddr *src, struct sockaddr *dst, uint8_t proto, struct sockaddr *ret)
{ (void)src; (void)dst; (void)proto; (void)ret; return -1; }
int getifaddr_in6(const char *ifn, int af, struct in6_addr *a)
{ (void)ifn; return inet_pton(AF_INET6, af == AF_INET ? "::ffff:203.0.113.7" : "2001:db8::7", a) == 1 ? 0 : -1; }
int port_in_use(const char *ifn, unsigned port, int proto, const char *ia, unsigned ip)
{ (void)ifn; (void)proto; (void)ia; (void)ip; return port == 22; }
int upnp_find_inboundpinhole(const char *ra, unsigned short rp, const char *ia, unsigned short ip, int pr,
                             char *de, int dl, unsigned int *lt)
{ (void)ra; (void)rp; (void)ia; (void)pr; if (ip != 22) return -2; if (de) snprintf(de, dl, "pinhole"); if (lt) *lt = 100; return 7; }
int sendto_or_schedule(int s, const void *b, size_t n, int f, const struct sockaddr *d, socklen_t l)
{ (void)s; (void)f; (void)d; (void)l; volatile unsigned char x = 0; for (size_t i = 0; i < n; i++) x ^= ((const unsigned char *)b)[i]; return (int)n; }
int sendto_or_schedule2(int s, const void *b, size_t n, int f, const struct sockaddr *d, socklen_t l, const struct sockaddr_in6 *src)
{ (void)src; return sendto_or_schedule(s, b, n, f, d, l); }
