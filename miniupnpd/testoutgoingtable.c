/* unit test of outgoing_table.c */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include "outgoing_table.h"

static struct in6_addr
addr(const char * s)
{
	struct in6_addr a;
	assert(inet_pton(AF_INET6, s, &a) == 1);
	return a;
}

/* An unlinked IPv4 UDP binding of iport out on eport, with one peer
 * raddr:rport, as PCP fills it. nonce: the last byte of the nonce. */
static struct outgoing_entry *
newbinding(unsigned short iport, unsigned short eport, const char * raddr,
           unsigned short rport, unsigned int timestamp, unsigned char nonce)
{
	struct outgoing_entry * b = outgoing_table_new(1);
	assert(b != NULL && b->npeers == 1);
	b->family = AF_INET;
	b->proto = IPPROTO_UDP;
	b->iaddr = addr("::ffff:192.0.2.10");
	b->iport = iport;
	b->eaddr = addr("::ffff:198.51.100.1");
	b->eport = eport;
	b->nonce[11] = nonce;
	b->peers[0].raddr = addr(raddr);
	b->peers[0].rport = rport;
	b->peers[0].timestamp = timestamp;
	return b;
}

/* a binding is found by its key, and its peers by their remote */
static void
test_key(void)
{
	struct outgoing_entry * b, * x;
	struct in6_addr r1 = addr("::ffff:203.0.113.1");

	outgoing_table_clear();
	b = newbinding(5000, 6000, "::ffff:203.0.113.1", 80, 100, 1);
	/* unlinked: not found */
	assert(outgoing_table_find(b) == NULL);
	x = outgoing_table_link(b);
	assert(x == b && outgoing_table_find(b) == b);
	assert(outgoing_table_count() == 1 && outgoing_table_peer_count() == 1);
	assert(outgoing_table_find_peer(b, &r1, 80) == &b->peers[0]);
	assert(outgoing_table_find_peer(b, &r1, 81) == NULL);
	/* another external port is another binding */
	x = outgoing_table_link(newbinding(5000, 6001, "::ffff:203.0.113.1", 80, 100, 1));
	assert(x != b && outgoing_table_count() == 2);
	/* the walk sees each binding once */
	assert(outgoing_table_next(NULL) != NULL);
	assert(outgoing_table_next(outgoing_table_next(NULL)) != NULL);
	assert(outgoing_table_next(outgoing_table_next(outgoing_table_next(NULL))) == NULL);
	assert(outgoing_table_next(NULL) != outgoing_table_next(outgoing_table_next(NULL)));
	outgoing_table_clear();
	assert(outgoing_table_next(NULL) == NULL);
	assert(outgoing_table_count() == 0 && outgoing_table_peer_count() == 0);
}

/* a binding of the key takes the peers of a new one: a renewal, or one more */
static void
test_merge(void)
{
	struct outgoing_entry * b, * x;
	struct in6_addr r1 = addr("::ffff:203.0.113.1"), r2 = addr("::ffff:203.0.113.2");
	int i;
	char a[INET6_ADDRSTRLEN];

	outgoing_table_clear();
	b = outgoing_table_link(newbinding(5000, 6000, "::ffff:203.0.113.1", 80, 100, 1));
	/* the same peer: its expiry and the nonce change, nothing is added */
	x = outgoing_table_link(newbinding(5000, 6000, "::ffff:203.0.113.1", 80, 200, 2));
	assert(x == b && b->npeers == 1 && b->peers[0].timestamp == 200);
	assert(b->nonce[11] == 2);
	assert(outgoing_table_count() == 1 && outgoing_table_peer_count() == 1);
	/* another peer: added */
	x = outgoing_table_link(newbinding(5000, 6000, "::ffff:203.0.113.2", 443, 300, 2));
	assert(x == b && b->npeers == 2 && outgoing_table_peer_count() == 2);
	assert(outgoing_table_find_peer(b, &r2, 443)->timestamp == 300);
	assert(outgoing_table_find_peer(b, &r1, 80)->timestamp == 200);
	/* enough peers to move the array several times */
	for(i = 0; i < 40; i++) {
		snprintf(a, sizeof(a), "::ffff:203.0.114.%d", i);
		assert(outgoing_table_link(newbinding(5000, 6000, a, 80, (unsigned int)i, 2)) == b);
	}
	assert(b->npeers == 42 && outgoing_table_peer_count() == 42);
	assert(outgoing_table_find_peer(b, &r2, 443)->timestamp == 300);
	outgoing_table_clear();
}

/* a peer goes, and the binding with its last one */
static void
test_remove(void)
{
	struct outgoing_entry * b;
	struct in6_addr r1 = addr("::ffff:203.0.113.1"), r2 = addr("::ffff:203.0.113.2");
	struct outgoing_entry key;

	outgoing_table_clear();
	b = outgoing_table_link(newbinding(5000, 6000, "::ffff:203.0.113.1", 80, 100, 1));
	outgoing_table_link(newbinding(5000, 6000, "::ffff:203.0.113.2", 80, 100, 1));
	key = *b;
	outgoing_table_remove_peer(b, outgoing_table_find_peer(b, &r1, 80));
	assert(outgoing_table_find(&key) == b && b->npeers == 1);
	assert(outgoing_table_find_peer(b, &r2, 80) == &b->peers[0]);
	assert(outgoing_table_peer_count() == 1);
	outgoing_table_remove_peer(b, &b->peers[0]);
	assert(outgoing_table_find(&key) == NULL);
	assert(outgoing_table_count() == 0 && outgoing_table_peer_count() == 0);
	b = outgoing_table_link(newbinding(5000, 6000, "::ffff:203.0.113.1", 80, 100, 1));
	outgoing_table_link(newbinding(5000, 6000, "::ffff:203.0.113.2", 80, 100, 1));
	outgoing_table_remove(b);
	assert(outgoing_table_count() == 0 && outgoing_table_peer_count() == 0);
}

/* expiry: the peers past it go, a binding with its last one; a peer
 * without expiry stays */
static void
test_expire(void)
{
	struct outgoing_entry * b, * c;
	struct in6_addr r2 = addr("::ffff:203.0.113.2"), r3 = addr("::ffff:203.0.113.3");

	outgoing_table_clear();
	b = outgoing_table_link(newbinding(5000, 6000, "::ffff:203.0.113.1", 80, 100, 1));
	outgoing_table_link(newbinding(5000, 6000, "::ffff:203.0.113.2", 80, 200, 1));
	outgoing_table_link(newbinding(5000, 6000, "::ffff:203.0.113.3", 80, 0, 1));
	c = outgoing_table_link(newbinding(5001, 6001, "::ffff:203.0.113.1", 80, 100, 2));
	assert(b != c && outgoing_table_count() == 2 && outgoing_table_peer_count() == 4);
	assert(outgoing_table_expire(99) == 0);
	assert(outgoing_table_expire(100) == 2);
	assert(outgoing_table_count() == 1 && outgoing_table_peer_count() == 2);
	assert(b->npeers == 2 && outgoing_table_find_peer(b, &r2, 80) != NULL &&
	       outgoing_table_find_peer(b, &r3, 80) != NULL);
	assert(outgoing_table_expire(1000) == 1);
	assert(b->npeers == 1 && outgoing_table_find_peer(b, &r3, 80) != NULL);
	outgoing_table_clear();
}

/* the change counter: a new binding, a merged peer, a removed peer and a
 * removed binding each count one; a lookup counts nothing */
static void
test_changes(void)
{
	struct outgoing_entry * b;
	unsigned long n;

	outgoing_table_clear();
	n = outgoing_table_changes();
	b = outgoing_table_link(newbinding(5000, 6000, "::ffff:203.0.113.1", 80, 100, 1));
	assert(outgoing_table_changes() == n + 1);
	outgoing_table_link(newbinding(5000, 6000, "::ffff:203.0.113.2", 80, 200, 1));
	assert(outgoing_table_changes() == n + 2);
	assert(outgoing_table_next(NULL) == b && outgoing_table_changes() == n + 2);
	outgoing_table_remove_peer(b, &b->peers[0]);
	assert(outgoing_table_changes() == n + 3);
	outgoing_table_remove(b);
	assert(outgoing_table_changes() == n + 4);
}

/* the dump: a header, a line per binding, a line per peer */
static void
test_dump(void)
{
	char path[] = "/tmp/testoutgoingtable.XXXXXX";
	char line[512];
	FILE * f;
	int fd, n = 0;

	outgoing_table_clear();
	outgoing_table_link(newbinding(5000, 6000, "::ffff:203.0.113.1", 80, 100, 1));
	outgoing_table_link(newbinding(5000, 6000, "::ffff:203.0.113.2", 443, 200, 1));
	fd = mkstemp(path);
	assert(fd >= 0);
	f = fdopen(fd, "w+");
	assert(f != NULL);
	outgoing_table_dump(f);
	rewind(f);
	assert(f != NULL);
	while(fgets(line, sizeof(line), f) != NULL) {
		switch(n++) {
		case 0:
			assert(strcmp(line, "# outgoing table: 1 bindings, 2 peers\n") == 0);
			break;
		case 1:
			assert(strcmp(line, "PEER IPv4 UDP [192.0.2.10]:5000 -> [198.51.100.1]:6000"
			                    " nonce=000000000000000000000001\n") == 0);
			break;
		case 2:
			assert(strcmp(line, "\tpeer [203.0.113.1]:80 expiry=100\n") == 0);
			break;
		case 3:
			assert(strcmp(line, "\tpeer [203.0.113.2]:443 expiry=200\n") == 0);
			break;
		}
	}
	fclose(f);
	unlink(path);
	assert(n == 4);
	outgoing_table_clear();
}

int
main(void)
{
	test_key();
	test_merge();
	test_remove();
	test_expire();
	test_changes();
	test_dump();
	printf("testoutgoingtable: OK\n");
	return 0;
}
