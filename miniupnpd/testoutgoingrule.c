/* MiniUPnP project
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

/* outgoing_rule_delete() against the firewall of the kernel: run it in a
 * network namespace of its own (testoutgoingrule.sh). One peer of a
 * binding goes, the other peer and the port mapping on the same external
 * port stay, and OUTGOING_RULE_DELETE_MAX peers go in one call. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "config.h"
#include "commonrdr.h"
#ifdef USE_NFTABLES
#include "netfilter_nft/nftnlrdr.h"
#else
#include "netfilter/iptcrdr.h"
#endif

#define IFNAME	"wan0"
#define EADDR	"198.51.100.1"
#define IADDR	"192.168.1.10"
#define RADDR	"203.0.113.1"
#define EPORT	40000
#define IPORT	5000

static int failed;

#define CHECK(c) do { if(!(c)) { \
	fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #c); \
	failed = 1; } } while(0)

static int
add_peer(unsigned short rport)
{
	return add_peer_redirect_rule2(IFNAME, RADDR, rport, EADDR, EPORT,
	                               IADDR, IPORT, IPPROTO_TCP, "peer", 0);
}

static void
key_of(struct outgoing_rule_key * k, unsigned short rport)
{
	memset(k, 0, sizeof(*k));
	k->iaddr = inet_addr(IADDR);
	k->raddr = inet_addr(RADDR);
	k->iport = IPORT;
	k->rport = rport;
	k->eport = EPORT;
	k->proto = IPPROTO_TCP;
}

/* the number of PEER rules to RADDR, and in *rport the remote port of the
 * last one. iptables also lists the MASQUERADE rule of a port mapping. */
static int
count_peers(unsigned short * rport)
{
	char iaddr[INET_ADDRSTRLEN], rhost[INET_ADDRSTRLEN], desc[64];
	unsigned short eport, iport, p;
	unsigned int timestamp;
	int proto, i, n = 0;

	for(i = 0; get_peer_rule_by_index(i, NULL, &eport, iaddr, sizeof(iaddr),
	                                  &iport, &proto, desc, sizeof(desc),
	                                  rhost, sizeof(rhost), &p, &timestamp,
	                                  NULL, NULL) >= 0; i++) {
		if(strcmp(rhost, RADDR) != 0)
			continue;
		n++;
		*rport = p;
	}
	return n;
}

int
main(void)
{
	struct outgoing_rule_key keys[OUTGOING_RULE_DELETE_MAX + 1];
	char iaddr[INET_ADDRSTRLEN];
	unsigned short iport, rport = 0;
	int i;

	openlog("testoutgoingrule", LOG_PERROR, LOG_USER);
	if(init_redirect() < 0) {
		fprintf(stderr, "init_redirect() failed\n");
		return 1;
	}

	/* a port mapping and two peers of one binding on EPORT */
	CHECK(add_redirect_rule2(IFNAME, "", EPORT, IADDR, IPORT, IPPROTO_TCP, "map", 0) >= 0);
	CHECK(add_peer(6001) >= 0);
	CHECK(add_peer(6002) >= 0);
	CHECK(count_peers(&rport) == 2);
#ifndef USE_NFTABLES
	/* the DSCP rules of peer 6001, both ways (PCP FLOWDATA): nft has none */
	CHECK(add_peer_dscp_rule2(IFNAME, RADDR, 6001, 46, IADDR, IPORT, IPPROTO_TCP, "up", 0) >= 0);
	CHECK(add_peer_dscp_rule2(IFNAME, IADDR, IPORT, 46, RADDR, 6001, IPPROTO_TCP, "down", 0) >= 0);
#endif

	/* one peer goes, by its remote: the other one and the mapping stay */
	key_of(&keys[0], 6001);
	CHECK(outgoing_rule_delete(keys, 1) == 0);
	CHECK(keys[0].result == 0);
	CHECK(count_peers(&rport) == 1);
	CHECK(rport == 6002);
	CHECK(get_redirect_rule(IFNAME, EPORT, IPPROTO_TCP, iaddr, sizeof(iaddr), &iport,
	                        NULL, 0, NULL, 0, NULL, NULL, NULL) == 0);

	/* a peer without a rule says so */
	CHECK(outgoing_rule_delete(keys, 1) == 0);
	CHECK(keys[0].result == -2);
	CHECK(count_peers(&rport) == 1);

	/* OUTGOING_RULE_DELETE_MAX peers go in one call */
	for(i = 0; i < OUTGOING_RULE_DELETE_MAX; i++) {
		CHECK(add_peer(7000 + i) >= 0);
		key_of(&keys[i], 7000 + i);
	}
	CHECK(count_peers(&rport) == OUTGOING_RULE_DELETE_MAX + 1);
	CHECK(outgoing_rule_delete(keys, OUTGOING_RULE_DELETE_MAX) == 0);
	for(i = 0; i < OUTGOING_RULE_DELETE_MAX; i++)
		CHECK(keys[i].result == 0);
	CHECK(count_peers(&rport) == 1);
	CHECK(rport == 6002);

	/* one more is refused, and nothing changes */
	key_of(&keys[OUTGOING_RULE_DELETE_MAX], 6002);
	CHECK(outgoing_rule_delete(keys, OUTGOING_RULE_DELETE_MAX + 1) < 0);
	CHECK(count_peers(&rport) == 1);

	shutdown_redirect();
	printf("testoutgoingrule: %s\n", failed ? "FAILED" : "OK");
	return failed;
}
