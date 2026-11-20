/* Test of the rule cache of nftnlrdr_misc.c against the nf_tables of the
 * kernel, while another program commits all the time: each lookup finds
 * the ruleset changed and reads the chain again, and a read the commits cut
 * short must not leave answers for the next request to take as its own.
 * It changes the ruleset of its network namespace: see testnftcache.sh,
 * which runs it in a container.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#include "config.h"
#include "netfilter_nft/nftnlrdr.h"

static int failures;

unsigned int
memmap_map_expiry(unsigned short eport, int proto)
{
	(void)eport; (void)proto;
	return 0;
}
time_t upnp_time(void) { return time(NULL); }
void memmap_remote_peers_partial(void) { }

static void
check(const char * name, int ok)
{
	printf("%s %s\n", ok ? "PASS" : "FAIL", name);
	if(!ok)
		failures++;
}

#define N 300
#define LOOKUPS 2000

int
main(void)
{
	char iaddr[32];
	unsigned short iport;
	int i, ok, found = 0, unknown = 0, wrong = 0;

	if(init_redirect() < 0) {
		printf("FAIL init_redirect\n");
		return 1;
	}
	for(i = 0, ok = 1; i < N; i++)
		ok &= add_redirect_rule2("wan0", NULL, (unsigned short)(10000 + i), "10.0.0.2",
		                         (unsigned short)(20000 + i), IPPROTO_TCP, "", 0) >= 0;
	check("redirect rules added", ok);
	ok = system("sh -c 'while :; do nft add table inet churn; nft delete table inet churn; "
	            "done' >/dev/null 2>&1 & echo $! > /tmp/churn.pid") == 0;
	for(i = 0; i < LOOKUPS; i++) {
		unsigned short eport = (unsigned short)(10000 + (i * 7) % N);
		int r = get_redirect_rule("wan0", eport, IPPROTO_TCP, iaddr, sizeof(iaddr), &iport,
		                          NULL, 0, NULL, 0, NULL, NULL, NULL);
		if(r == 0 && iport == eport + 10000)
			found++;
		else if(r == -1)
			unknown++;	/* the chain could not be read */
		else
			wrong++;
	}
	(void)system("kill $(cat /tmp/churn.pid)");
	printf("info: %d found, %d not known, %d wrong of %d lookups\n", found, unknown, wrong,
	       LOOKUPS);
	check("lookups while another program commits: none wrong", ok && wrong == 0);
	check("most lookups find their rule", found > LOOKUPS / 2);
	printf("testnftcache: %s\n", failures ? "FAILED" : "all tests passed");
	return failures ? 1 : 0;
}
