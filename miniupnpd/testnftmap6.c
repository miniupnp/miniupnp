/* Test of the map6 rules of nftpinhole.c against the nf_tables of the
 * kernel: lookups by key, deletes, the walk by index, with and without a
 * table of its own for IPv6. It changes the ruleset of its network
 * namespace: see testnftmap6.sh, which runs it in a container.
 *
 *   ./testnftmap6          IPv4 and IPv6 in one inet table
 *   ./testnftmap6 split    upnp_nftables_family_split=yes: an ip6 table
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "config.h"
#include "netfilter_nft/nftnlrdr.h"
#include "fwmap6.h"

static int failures;

unsigned int
memmap_map_expiry(unsigned short eport, int proto)
{
	(void)eport; (void)proto;
	return 0;
}

static void
check(const char * name, int ok)
{
	printf("%s %s\n", ok ? "PASS" : "FAIL", name);
	if(!ok)
		failures++;
}

#define N 200

int
main(int argc, char * argv[])
{
	char a[INET6_ADDRSTRLEN], r[INET6_ADDRSTRLEN], i6[INET6_ADDRSTRLEN], cmd[512];
	unsigned short rport, iport;
	u_int64_t p;
	int i, ok, proto, n;

	if(argc > 1 && strcmp(argv[1], "split") == 0)
		set_rdr_name(RDR_FAMILY_SPLIT, "yes");
	if(init_redirect() < 0) {
		printf("FAIL init_redirect\n");
		return 1;
	}
	for(i = 0, ok = 1; i < N; i++) {
		snprintf(a, sizeof(a), "2001:db8::%x", i + 1);
		ok &= add_map6_rule("wan0", NULL, 0, a, (unsigned short)(2000 + i), IPPROTO_TCP,
		                    "test", 0) == 0;
	}
	check("map6 rules added", ok);
	for(i = 0, ok = 1; i < N; i++) {
		snprintf(a, sizeof(a), "2001:db8::%x", i + 1);
		ok &= get_map6_packets(NULL, 0, a, (unsigned short)(2000 + i), IPPROTO_TCP, &p) == 0;
	}
	check("each is found by its key", ok &&
	      get_map6_packets(NULL, 0, "2001:db8::1", 1999, IPPROTO_TCP, &p) == -2);
	for(n = 0; get_map6_rule_at(n, r, sizeof(r), &rport, i6, sizeof(i6), &iport, &proto,
	                            NULL, 0) == 0; n++)
		;
	check("the walk by index finds them all", n == N);
	/* deletes of half: each is gone, the others stay found */
	for(i = 0, ok = 1; i < N; i += 2) {
		snprintf(a, sizeof(a), "2001:db8::%x", i + 1);
		ok &= delete_map6_rule(NULL, 0, a, (unsigned short)(2000 + i), IPPROTO_TCP) == 0;
	}
	check("half deleted", ok);
	for(i = 0, ok = 1; i < N; i++) {
		snprintf(a, sizeof(a), "2001:db8::%x", i + 1);
		ok &= get_map6_packets(NULL, 0, a, (unsigned short)(2000 + i), IPPROTO_TCP, &p) ==
		      (i % 2 == 0 ? -2 : 0);
	}
	check("the deleted are gone, the others found", ok);
	for(n = 0; get_map6_rule_at(n, r, sizeof(r), &rport, i6, sizeof(i6), &iport, &proto,
	                            NULL, 0) == 0; n++)
		;
	check("the walk finds the rest", n == N / 2);
	/* another program deletes one: the cache sees it */
	ok = system("nft -a list ruleset | grep -q 'dport 2001'") == 0;
	snprintf(cmd, sizeof(cmd), "nft delete rule %s filter miniupnpd handle $(nft -a list chain %s "
	         "filter miniupnpd | sed -n 's/.*dport 2001 .*handle \\([0-9]*\\).*/\\1/p')",
	         argc > 1 ? "ip6" : "inet", argc > 1 ? "ip6" : "inet");
	ok &= system(cmd) == 0;
	check("a rule another program deleted is not found",
	      ok && get_map6_packets(NULL, 0, "2001:db8::2", 2001, IPPROTO_TCP, &p) == -2 &&
	      get_map6_packets(NULL, 0, "2001:db8::4", 2003, IPPROTO_TCP, &p) == 0);
	printf("testnftmap6%s: %s\n", argc > 1 ? " split" : "", failures ? "FAILED" : "all tests passed");
	return failures ? 1 : 0;
}
