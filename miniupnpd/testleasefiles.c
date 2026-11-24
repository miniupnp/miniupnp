/* MiniUPnP project
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

/* unit test of lease_files.c: the files a save writes from the tables, and
 * when it writes them */
#include "config.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "upnpglobalvars.h"
#include "upnputils.h"
#include "lease_table.h"
#include "outgoing_table.h"
#include "lease_files.h"

#ifndef ENABLE_LEASEFILE
int
main(void)
{
	printf("testleasefiles: skipped, built without ENABLE_LEASEFILE\n");
	return 0;
}
#else /* ENABLE_LEASEFILE */

/* what lease_files.c takes from the daemon */
const char * lease_file = NULL;
static time_t now = 1000;

time_t
upnp_time(void)
{
	return now;
}

const char *
proto_itoa(int proto)
{
	/* as upnputils.c, for the protocols of the rows here */
	return proto == IPPROTO_TCP ? "TCP" : proto == IPPROTO_UDP ? "UDP" : "?";
}

static char dir[] = "/tmp/testleasefilesXXXXXX";
static char base[256];

static struct in6_addr
addr(const char * s)
{
	struct in6_addr a;
	assert(inet_pton(AF_INET6, s, &a) == 1);
	return a;
}

/* the whole of a file, or NULL if there is none */
static char *
slurp(const char * suffix)
{
	char path[300];
	FILE * f;
	long n;
	char * s;
	snprintf(path, sizeof(path), "%s%s", base, suffix);
	f = fopen(path, "r");
	if(f == NULL)
		return NULL;
	fseek(f, 0, SEEK_END);
	n = ftell(f);
	rewind(f);
	s = malloc(n + 1);
	assert(s != NULL);
	assert(fread(s, 1, n, f) == (size_t)n);
	s[n] = '\0';
	fclose(f);
	return s;
}

/* The lines of a file after its header line, which holds last_id */
static void
expect(const char * suffix, const char * want)
{
	char * got = slurp(suffix);
	const char * body = got != NULL ? strchr(got, '\n') : NULL;
	if(body == NULL || strcmp(body + 1, want) != 0) {
		fprintf(stderr, "%s%s:\n--- got\n%s--- want\n%s", base, suffix,
		        got ? got : "(none)\n", want);
		abort();
	}
	free(got);
}

static void
remove_files(void)
{
	static const char * const suffixes[] = { ".mappings", ".filters", ".outgoing" };
	char path[300];
	unsigned int i;
	for(i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); i++) {
		snprintf(path, sizeof(path), "%s%s", base, suffixes[i]);
		unlink(path);
	}
}

/* A linked row. family AF_INET: iaddr is ::ffff:a.b.c.d. */
static struct lease_entry *
add_row(unsigned long long id, int kind, int family, int proto, unsigned short eport,
        const char * iaddr, unsigned short iport, const char * eaddr,
        unsigned int expiry, const char * label, int nfilters)
{
	struct lease_entry * e = lease_table_new(nfilters);
	assert(e != NULL);
	e->id = id;
	e->kind = (unsigned char)kind;
	e->family = (unsigned char)family;
	e->proto = (unsigned char)proto;
	e->eport = eport;
	e->iport = iport;
	e->iaddr = addr(iaddr);
	if(eaddr != NULL)
		e->eaddr = addr(eaddr);
	e->timestamp = expiry;
	e->label = label;
	return e;
}

static void
poll_now(int idle)
{
	struct timeval tv = { 60, 0 };
	lease_files_poll(idle, &tv);
}

/* the lines of each file, and what they hold */
static void
test_contents(void)
{
	struct lease_entry * e;
	struct outgoing_entry * b;
	int i;

	lease_table_clear();
	outgoing_table_clear();
	remove_files();
	/* UPnP IPv4 with a remote host, a label to escape */
	e = add_row(1, MAP_KIND_UPNP, AF_INET, IPPROTO_TCP, 40001, "::ffff:192.168.1.10", 8080,
	            "::ffff:198.51.100.1", now + 3600, "cam|era\\1\n", 1);
	e->filters[0].raddr = addr("::ffff:203.0.113.7");
	e->filters[0].prefix = 128;
	lease_table_link(e);
	/* NAT-PMP, no expiry, no label */
	lease_table_link(add_row(2, MAP_KIND_NATPMP, AF_INET, IPPROTO_UDP, 40002, "::ffff:192.168.1.11",
	                         5060, NULL, 0, NULL, 0));
	/* PCP with its nonce and a label of NA */
	e = add_row(3, MAP_KIND_PCP, AF_INET, IPPROTO_UDP, 40003, "::ffff:192.168.1.12", 7000,
	            "::ffff:198.51.100.1", now + 60, "NA", 0);
	for(i = 0; i < MAP_NONCE_LEN; i++)
		e->nonce[i] = (unsigned char)(0x11 * i);
	lease_table_link(e);
	/* UPnP IPv6 map, two rules: any remote, and a /64 */
	e = add_row(4, MAP_KIND_UPNP, AF_INET6, IPPROTO_UDP, 9000, "2001:db8::10", 9000,
	            "2001:db8::10", now + 100, NULL, 2);
	e->filters[0].uid = 7;
	e->filters[1].raddr = addr("2001:db8:1::");
	e->filters[1].prefix = 64;
	e->filters[1].rport = 53;
	e->filters[1].uid = 8;
	lease_table_link(e);
	/* a PEER binding with two peers */
	b = outgoing_table_new(2);
	assert(b != NULL);
	b->family = AF_INET;
	b->proto = IPPROTO_TCP;
	b->iaddr = addr("::ffff:192.168.1.13");
	b->iport = 5000;
	b->eaddr = addr("::ffff:198.51.100.1");
	b->eport = 6000;
	b->nonce[11] = 0xab;
	b->peers[0].raddr = addr("::ffff:203.0.113.1");
	b->peers[0].rport = 80;
	b->peers[0].timestamp = now + 30;
	b->peers[1].raddr = addr("::ffff:203.0.113.2");
	b->peers[1].rport = 443;
	b->peers[1].timestamp = now + 40;
	outgoing_table_link(b);

	poll_now(1);
	{
		/* the expiry is unix time: the clock of the save plus what is left */
		long long t0 = (long long)time(NULL);
		char * m = slurp(".mappings");
		unsigned long long id;
		unsigned int exp;
		assert(m != NULL);
		assert(strncmp(m, "LEASE-MAPPINGS 1 last_id=", 25) == 0);
		assert(strstr(m, "\nid|kind|family|proto|eport|iport|iaddr|eaddr|nonce|expiry|filters|label\n") != NULL);
		assert(sscanf(strstr(m, "\n1|"), "\n%llu|UPNP|IPv4|TCP|40001|8080|192.168.1.10|198.51.100.1|NA|%u|1|",
		              &id, &exp) == 2);
		assert(id == 1 && (long long)exp >= t0 + 3599 && (long long)exp <= t0 + 3601);
		assert(strstr(m, "|cam\\|era\\\\1\\n\n") != NULL);
		assert(strstr(m, "\n2|NAT-PMP|IPv4|UDP|40002|5060|192.168.1.11|NA|NA|0|0|NA\n") != NULL);
		assert(strstr(m, "\n3|PCP-M|IPv4|UDP|40003|7000|192.168.1.12|198.51.100.1|00112233445566778899aabb|") != NULL);
		assert(strstr(m, "|0|\\x4EA\n") != NULL);
		assert(strstr(m, "\n4|UPNP|IPv6|UDP|9000|9000|2001:db8::10|2001:db8::10|NA|") != NULL);
		free(m);
	}
	{
		char * f = slurp(".filters");
		assert(f != NULL && strncmp(f, "LEASE-FILTERS 1 last_id=", 24) == 0);
		assert(strstr(f, "\nmap|raddr|rprefix|rport|uid\n") != NULL);
		assert(strstr(f, "\n1|203.0.113.7|32|0|NA\n") != NULL);
		assert(strstr(f, "\n4|NA|0|0|7\n") != NULL);
		assert(strstr(f, "\n4|2001:db8:1::|64|53|8\n") != NULL);
		free(f);
	}
	{
		char * o = slurp(".outgoing");
		assert(o != NULL && strncmp(o, "LEASE-OUTGOING 1 last_id=", 25) == 0);
		assert(strstr(o, "\nfamily|proto|iaddr|iport|eaddr|eport|nonce|raddr|rport|expiry|label\n") != NULL);
		assert(strstr(o, "\nIPv4|TCP|192.168.1.13|5000|198.51.100.1|6000|0000000000000000000000ab|203.0.113.1|80|") != NULL);
		assert(strstr(o, "\nIPv4|TCP|192.168.1.13|5000|198.51.100.1|6000|0000000000000000000000ab|203.0.113.2|443|") != NULL);
		free(o);
	}
	lease_table_clear();
	outgoing_table_clear();
	now += LEASE_FILES_MIN_GAP;
	poll_now(1);
	expect(".mappings", "id|kind|family|proto|eport|iport|iaddr|eaddr|nonce|expiry|filters|label\n");
	expect(".filters", "map|raddr|rprefix|rport|uid\n");
	expect(".outgoing", "family|proto|iaddr|iport|eaddr|eport|nonce|raddr|rport|expiry|label\n");
}

/* when a save runs: idle after LEASE_FILES_MIN_GAP, or after
 * LEASE_FILES_MAX_DELAY busy; only the changed files are written */
static void
test_timing(void)
{
	struct lease_entry * e;
	struct timeval tv;
	struct stat st;
	char path[300];
	ino_t ino;

	lease_table_clear();
	outgoing_table_clear();
	now += LEASE_FILES_MIN_GAP;
	poll_now(1);	/* the clear is saved */
	remove_files();
	now += 100;
	e = add_row(10, MAP_KIND_UPNP, AF_INET, IPPROTO_TCP, 41000, "::ffff:192.168.1.10", 80,
	            NULL, 0, "a", 0);
	lease_table_link(e);
	/* busy: no save before the delay; the timeout says when to come back */
	tv.tv_sec = 60;
	tv.tv_usec = 0;
	lease_files_poll(0, &tv);
	assert(slurp(".mappings") == NULL);
	assert(tv.tv_sec <= LEASE_FILES_MAX_DELAY);
	now += LEASE_FILES_MAX_DELAY - 1;
	lease_files_poll(0, &tv);
	assert(slurp(".mappings") == NULL);
	now += 1;
	lease_files_poll(0, &tv);
	expect(".mappings", "id|kind|family|proto|eport|iport|iaddr|eaddr|nonce|expiry|filters|label\n"
	       "10|UPNP|IPv4|TCP|41000|80|192.168.1.10|NA|NA|0|0|a\n");
	/* only .mappings changed: the others are not written */
	assert(slurp(".filters") == NULL && slurp(".outgoing") == NULL);
	/* idle, but within the gap of the last save: no save */
	assert(lease_table_set_label(e, "b") == 0);
	lease_files_poll(1, &tv);
	expect(".mappings", "id|kind|family|proto|eport|iport|iaddr|eaddr|nonce|expiry|filters|label\n"
	       "10|UPNP|IPv4|TCP|41000|80|192.168.1.10|NA|NA|0|0|a\n");
	now += LEASE_FILES_MIN_GAP;
	lease_files_poll(1, &tv);
	expect(".mappings", "id|kind|family|proto|eport|iport|iaddr|eaddr|nonce|expiry|filters|label\n"
	       "10|UPNP|IPv4|TCP|41000|80|192.168.1.10|NA|NA|0|0|b\n");
	/* nothing changed: the file is left alone */
	snprintf(path, sizeof(path), "%s.mappings", base);
	assert(stat(path, &st) == 0);
	ino = st.st_ino;
	now += 100;
	lease_files_poll(1, &tv);
	assert(stat(path, &st) == 0 && st.st_ino == ino);
	/* flush writes at once */
	assert(lease_table_set_label(e, "c") == 0);
	assert(lease_files_flush() == 0);
	expect(".mappings", "id|kind|family|proto|eport|iport|iaddr|eaddr|nonce|expiry|filters|label\n"
	       "10|UPNP|IPv4|TCP|41000|80|192.168.1.10|NA|NA|0|0|c\n");
	lease_table_clear();
}

/* a save which cannot write keeps the old files, and tries again later */
static void
test_failure(void)
{
	char bad[300];
	const char * good = lease_file;

	lease_table_clear();
	lease_files_flush();
	snprintf(bad, sizeof(bad), "%s/none/leases", dir);
	lease_file = bad;
	lease_table_link(add_row(20, MAP_KIND_NATPMP, AF_INET, IPPROTO_UDP, 42000,
	                         "::ffff:192.168.1.10", 80, NULL, 0, NULL, 0));
	now += 100;
	poll_now(1);	/* fails, logs once */
	lease_file = good;
	now += 1;
	poll_now(1);	/* waits for the back-off */
	assert(strstr(slurp(".mappings"), "42000") == NULL);
	now += LEASE_FILES_MAX_DELAY;
	poll_now(1);
	assert(strstr(slurp(".mappings"), "|42000|") != NULL);
	lease_table_clear();
}

int
main(void)
{
	assert(mkdtemp(dir) != NULL);
	snprintf(base, sizeof(base), "%s/leases", dir);
	lease_file = base;
	/* before the main loop: nothing is written */
	lease_table_link(add_row(99, MAP_KIND_UPNP, AF_INET, IPPROTO_TCP, 1, "::ffff:192.168.1.1",
	                         1, NULL, 0, NULL, 0));
	assert(lease_files_flush() == 0 && slurp(".mappings") == NULL);
	test_contents();
	test_timing();
	test_failure();
	remove_files();
	rmdir(dir);
	printf("testleasefiles: OK\n");
	return 0;
}

#endif /* ENABLE_LEASEFILE */
