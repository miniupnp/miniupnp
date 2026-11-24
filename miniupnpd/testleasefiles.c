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
const char * ext_if_name = "wan0";
#ifdef ENABLE_IPV6
const char * ext_if_name6 = "wan6";
#endif
enum lease_restore_mode lease_file_restore = LEASE_RESTORE_YES;
static time_t now = 1000;

time_t
upnp_time(void)
{
	return now;
}

const char *
proto_itoa(int proto)
{
	/* as upnputils.c: a protocol it has no name for is "*UNKNOWN*" */
	return proto == IPPROTO_TCP ? "TCP" : proto == IPPROTO_UDP ? "UDP" : "*UNKNOWN*";
}

int
proto_atoi(const char * protocol)
{
	/* as upnputils.c: TCP for a name it does not know */
	return strcmp(protocol, "UDP") == 0 ? IPPROTO_UDP : IPPROTO_TCP;
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
	static const char * const suffixes[] = { ".mappings", ".filters", ".outgoing", ".outgoing.peers", ".checksum" };
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
	/* NAT-PMP, no expiry, no label; made before (since kept) */
	e = add_row(2, MAP_KIND_NATPMP, AF_INET, IPPROTO_UDP, 40002, "::ffff:192.168.1.11",
	            5060, NULL, 0, NULL, 0);
	e->since = 1700000000;
	lease_table_link(e);
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
	b = outgoing_table_link(b);
	assert(b != NULL && b->id != 0);

	poll_now(1);
	{
		/* the expiry is unix time: the clock of the save plus what is left */
		long long t0 = (long long)time(NULL);
		char * m = slurp(".mappings");
		unsigned long long id;
		unsigned int exp, since;
		assert(m != NULL);
		assert(strncmp(m, "LEASE-MAPPINGS 1 last_id=", 25) == 0);
		assert(strstr(m, "\nid|kind|family|proto|eport|iport|iaddr|eaddr|nonce|since|expiry|ifname|filters|label\n") != NULL);
		assert(sscanf(strstr(m, "\n1|"), "\n%llu|UPNP|IPv4|TCP|40001|8080|192.168.1.10|198.51.100.1|NA|%u|%u|wan0|1|",
		              &id, &since, &exp) == 3);
		assert(id == 1 && (long long)exp >= t0 + 3599 && (long long)exp <= t0 + 3601);
		/* set when the row was linked */
		assert((long long)since >= t0 - 5 && (long long)since <= t0);
		assert(strstr(m, "|cam\\|era\\\\1\\n\n") != NULL);
		assert(strstr(m, "\n2|NAT-PMP|IPv4|UDP|40002|5060|192.168.1.11|NA|NA|1700000000|0|wan0|0|NA\n") != NULL);
		assert(strstr(m, "\n3|PCP-M|IPv4|UDP|40003|7000|192.168.1.12|198.51.100.1|00112233445566778899aabb|") != NULL);
		assert(strstr(m, "|0|\\x4EA\n") != NULL);
		assert(strstr(m, "\n4|UPNP|IPv6|UDP|9000|9000|2001:db8::10|2001:db8::10|NA|") != NULL);
#ifdef ENABLE_IPV6
		assert(strstr(m, "|wan6|2|NA\n") != NULL);	/* ext_ifname6 */
#else
		assert(strstr(m, "|wan0|2|NA\n") != NULL);
#endif
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
		char * o = slurp(".outgoing"), * ps = slurp(".outgoing.peers");
		char want[160];
		assert(o != NULL && strncmp(o, "LEASE-OUTGOING 1 last_id=", 25) == 0);
		assert(strstr(o, "\nid|family|proto|iaddr|iport|eaddr|eport|nonce|ifname|peers|label\n") != NULL);
		/* one line per binding, its peers counted */
		snprintf(want, sizeof(want),
		         "\n%llu|IPv4|TCP|192.168.1.13|5000|198.51.100.1|6000|0000000000000000000000ab|wan0|2|NA\n",
		         b->id);
		assert(strstr(o, want) != NULL);
		/* one line per peer, by the id of its binding */
		assert(ps != NULL && strncmp(ps, "LEASE-OUTGOING-PEERS 1 last_id=", 31) == 0);
		assert(strstr(ps, "\nbinding|raddr|rport|since|expiry\n") != NULL);
		snprintf(want, sizeof(want), "\n%llu|203.0.113.1|80|", b->id);
		assert(strstr(ps, want) != NULL);
		snprintf(want, sizeof(want), "\n%llu|203.0.113.2|443|", b->id);
		assert(strstr(ps, want) != NULL);
		free(o);
		free(ps);
	}
	lease_table_clear();
	outgoing_table_clear();
	now += LEASE_FILES_MIN_GAP;
	poll_now(1);
	expect(".mappings", "id|kind|family|proto|eport|iport|iaddr|eaddr|nonce|since|expiry|ifname|filters|label\n");
	expect(".filters", "map|raddr|rprefix|rport|uid\n");
	expect(".outgoing", "id|family|proto|iaddr|iport|eaddr|eport|nonce|ifname|peers|label\n");
	expect(".outgoing.peers", "binding|raddr|rport|since|expiry\n");
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
	e->since = 1700000000;
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
	expect(".mappings", "id|kind|family|proto|eport|iport|iaddr|eaddr|nonce|since|expiry|ifname|filters|label\n"
	       "10|UPNP|IPv4|TCP|41000|80|192.168.1.10|NA|NA|1700000000|0|wan0|0|a\n");
	/* only .mappings changed: the others are not written */
	assert(slurp(".filters") == NULL && slurp(".outgoing") == NULL && slurp(".outgoing.peers") == NULL);
	/* idle, but within the gap of the last save: no save */
	assert(lease_table_set_label(e, "b") == 0);
	lease_files_poll(1, &tv);
	expect(".mappings", "id|kind|family|proto|eport|iport|iaddr|eaddr|nonce|since|expiry|ifname|filters|label\n"
	       "10|UPNP|IPv4|TCP|41000|80|192.168.1.10|NA|NA|1700000000|0|wan0|0|a\n");
	now += LEASE_FILES_MIN_GAP;
	lease_files_poll(1, &tv);
	expect(".mappings", "id|kind|family|proto|eport|iport|iaddr|eaddr|nonce|since|expiry|ifname|filters|label\n"
	       "10|UPNP|IPv4|TCP|41000|80|192.168.1.10|NA|NA|1700000000|0|wan0|0|b\n");
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
	expect(".mappings", "id|kind|family|proto|eport|iport|iaddr|eaddr|nonce|since|expiry|ifname|filters|label\n"
	       "10|UPNP|IPv4|TCP|41000|80|192.168.1.10|NA|NA|1700000000|0|wan0|0|c\n");
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

/* What a load gave: the rows and bindings, and their labels copied */
#define MAX_GOT	16
static struct lease_entry * got[MAX_GOT];
static char got_label[MAX_GOT][64];
static int ngot;
static struct outgoing_entry * got_peer[MAX_GOT];
static int ngot_peer;

static void
take_map(struct lease_entry * e, void * arg)
{
	(void)arg;
	assert(ngot < MAX_GOT);
	snprintf(got_label[ngot], sizeof(got_label[ngot]), "%s", e->label ? e->label : "");
	e->label = NULL;
	got[ngot++] = e;
}

static void
take_peer(struct outgoing_entry * b, void * arg)
{
	(void)arg;
	assert(ngot_peer < MAX_GOT);
	b->label = NULL;
	got_peer[ngot_peer++] = b;
}

static void
free_got(void)
{
	int i;
	for(i = 0; i < ngot; i++)
		lease_table_free(got[i]);
	for(i = 0; i < ngot_peer; i++)
		outgoing_table_free(got_peer[i]);
	ngot = ngot_peer = 0;
}

static int
load(void)
{
	static const struct lease_files_restore r = { take_map, take_peer, NULL, NULL };
	free_got();
	return lease_files_load(&r);
}

static void
write_file(const char * suffix, const char * text)
{
	char path[300];
	FILE * f;
	snprintf(path, sizeof(path), "%s%s", base, suffix);
	f = fopen(path, "w");
	assert(f != NULL);
	fputs(text, f);
	fclose(f);
}

static void
unlink_file(const char * suffix)
{
	char path[300];
	snprintf(path, sizeof(path), "%s%s", base, suffix);
	unlink(path);
}

/* the row of id that a load gave, and its label */
static struct lease_entry *
got_id(unsigned long long id, const char ** label)
{
	int i;
	for(i = 0; i < ngot; i++)
		if(got[i]->id == id) {
			if(label != NULL)
				*label = got_label[i];
			return got[i];
		}
	return NULL;
}

static int
same_addr(const struct in6_addr * a, const char * s)
{
	struct in6_addr b = addr(s);
	return memcmp(a, &b, sizeof(b)) == 0;
}

/* what a save writes, a load gives back: every field, the filters with
 * their prefix and uid, the PEER peers; the expiry as time left */
static void
test_round_trip(void)
{
	struct lease_entry * e, * g;
	struct outgoing_entry * b;
	unsigned long long bid;
	const char * label;
	int i;

	lease_table_clear();
	outgoing_table_clear();
	e = add_row(1, MAP_KIND_UPNP, AF_INET, IPPROTO_TCP, 40001, "::ffff:192.168.1.10", 8080,
	            "::ffff:198.51.100.1", now + 3600, "cam|era\\1\n", 1);
	e->filters[0].raddr = addr("::ffff:203.0.113.0");
	e->filters[0].prefix = 120;
	e->filters[0].rport = 443;
	lease_table_link(e);
	/* SCTP: a protocol with no name, written by its number */
	e = add_row(2, MAP_KIND_PCP, AF_INET, 132, 40003, "::ffff:192.168.1.12", 7000,
	            NULL, 0, "NA", 0);
	for(i = 0; i < MAP_NONCE_LEN; i++)
		e->nonce[i] = (unsigned char)(0x11 * i);
	lease_table_link(e);
	e = add_row(3, MAP_KIND_UPNP, AF_INET6, IPPROTO_UDP, 9000, "2001:db8::10", 9000,
	            "2001:db8::10", now + 100, NULL, 2);
	e->filters[0].uid = 7;
	e->filters[1].raddr = addr("2001:db8:1::");
	e->filters[1].prefix = 64;
	e->filters[1].uid = 8;
	lease_table_link(e);
	/* a network of ::, written NA: its prefix is read in the family of the
	 * row */
	e = add_row(4, MAP_KIND_PCP, AF_INET6, IPPROTO_UDP, 9001, "2001:db8::11", 9001,
	            "2001:db8::11", 0, NULL, 1);
	e->filters[0].prefix = 64;
	lease_table_link(e);
	/* a binding of two peers; the second expires before the load */
	b = outgoing_table_new(2);
	assert(b != NULL);
	b->family = AF_INET;
	b->proto = IPPROTO_TCP;
	b->iaddr = addr("::ffff:192.168.1.13");
	b->iport = 5000;
	b->eaddr = addr("::ffff:198.51.100.1");
	b->eport = 6000;
	b->nonce[0] = 0xab;
	b->peers[0].raddr = addr("::ffff:203.0.113.1");
	b->peers[0].rport = 80;
	b->peers[0].timestamp = now + 30;
	b->peers[1].raddr = addr("::ffff:203.0.113.2");
	b->peers[1].rport = 81;
	b->peers[1].timestamp = now + 1;
	b = outgoing_table_link(b);
	assert(b != NULL);
	bid = b->id;
	assert(lease_files_flush() == 0);
	now += 1;

	assert(load() == 1 && ngot == 4 && ngot_peer == 1);
	g = got_id(1, &label);
	assert(g != NULL && g->kind == MAP_KIND_UPNP && g->family == AF_INET && g->proto == IPPROTO_TCP);
	assert(g->eport == 40001 && g->iport == 8080 && strcmp(label, "cam|era\\1\n") == 0);
	assert(g->since != 0 && g->since <= (unsigned int)time(NULL));
	assert(same_addr(&g->iaddr, "::ffff:192.168.1.10") && same_addr(&g->eaddr, "::ffff:198.51.100.1"));
	assert(g->nfilters == 1 && g->filters[0].prefix == 120 && g->filters[0].rport == 443);
	assert(same_addr(&g->filters[0].raddr, "::ffff:203.0.113.0"));
	/* the clocks may differ by the rounding of a second */
	assert(g->timestamp >= now + 3599 && g->timestamp <= now + 3601);
	g = got_id(2, &label);
	assert(g != NULL && g->kind == MAP_KIND_PCP && g->proto == 132);
	assert(g->timestamp == 0 && g->nonce[11] == 0xbb);
	assert(IN6_IS_ADDR_UNSPECIFIED(&g->eaddr) && strcmp(label, "NA") == 0);
	g = got_id(3, NULL);
	assert(g != NULL && g->family == AF_INET6 && g->nfilters == 2);
	assert(g->filters[0].uid + g->filters[1].uid == 15);
	assert(g->filters[0].prefix + g->filters[1].prefix == 64);
	g = got_id(4, NULL);
	assert(g != NULL && g->nfilters == 1 && g->filters[0].prefix == 64);
	assert(IN6_IS_ADDR_UNSPECIFIED(&g->filters[0].raddr));
	b = got_peer[0];
	assert(b->id == bid && b->eport == 6000 && b->iport == 5000 && b->nonce[0] == 0xab);
	assert(b->peers[0].rport == 80 && b->peers[0].timestamp >= now + 29);
	free_got();
	lease_table_clear();
	outgoing_table_clear();
}

/* a file written by hand: fields in another order, a field the reader does
 * not know, a missing field takes its default; bad and expired lines, and
 * a row whose filter count does not match, are skipped */
static void
test_hand_file(void)
{
	char text[2048];
	long long t = (long long)time(NULL) + 600;

	remove_files();
	snprintf(text, sizeof(text),
	         "LEASE-MAPPINGS 1 last_id=50 future=yes\n"
	         "kind|id|color|family|proto|iport|eport|iaddr|nonce|expiry|filters\n"
	         "NAT-PMP|10|red|IPv4|UDP|5060|40002|192.168.1.11|NA|%lld|0\n"
	         "PCP-M|11|red|IPv4|TCP|22|40003|192.168.1.12|00112233445566778899aabb|0|1\n"
	         "UPNP|12|red|IPv4|TCP|80|40004|192.168.1.13|NA|1|0\n"
	         "UPNP|13|red|IPv9|TCP|80|40005|192.168.1.13|NA|0|0\n"
	         "UPNP|14|red|IPv4|TCP|80|40006|192.168.1.13|NA|0\n"
	         "PCP-M|15|red|IPv4|TCP|23|40007|192.168.1.12|00112233445566778899aabb|0|2\n"
	         "PCP-M|16|red|IPv4|SCTP|0|40008|192.168.1.12|00112233445566778899aabb|0|0\n"
	         "PCP-M|17|red|IPv4|0|0|40009|192.168.1.12|00112233445566778899aabb|0|0\n",
	         t);
	write_file(".mappings", text);
	write_file(".filters", "LEASE-FILTERS 1\nmap|raddr|rport\n11|203.0.113.7|0\n15|203.0.113.8|0\n");
	/* written by hand: no .checksum */
	assert(load() == -1);
	unlink_file(".mappings.bad");
	unlink_file(".filters.bad");
	write_file(".mappings", text);
	write_file(".filters", "LEASE-FILTERS 1\nmap|raddr|rport\n11|203.0.113.7|0\n15|203.0.113.8|0\n");
	lease_files_ignore_checksum = 1;
	assert(load() == 1);
	lease_files_ignore_checksum = 0;
	/* 10, 11, 17 (protocol 0: all); 12 expired, 13 bad family, 14 too few
	 * fields, 15 of another save, 16 a protocol name the daemon does not
	 * write */
	assert(ngot == 3 && got_id(10, NULL) != NULL && got_id(11, NULL) != NULL);
	assert(got_id(17, NULL) != NULL && got_id(17, NULL)->proto == 0);
	assert(got_id(10, NULL)->timestamp >= now + 599 && got_id(10, NULL)->timestamp <= now + 601);
	assert(IN6_IS_ADDR_UNSPECIFIED(&got_id(10, NULL)->eaddr));
	/* no rprefix: one host */
	assert(got_id(11, NULL)->nfilters == 1 && got_id(11, NULL)->filters[0].prefix == 128);
	free_got();
	/* the ids of the files are kept from the rows of this run */
	lease_files_reserve_ids();
	assert(lease_table_last_id() >= 50);
	remove_files();
}

/* no .mappings: nothing; a file which is not ours: the set goes aside as
 * .bad, nothing is read, and the next save writes a new set */
static void
test_bad_files(void)
{
	char * bad;

	remove_files();
	assert(load() == 0 && ngot == 0);
	write_file(".mappings", "LEASE-MAPPINGS 1\nid|kind|family|proto|eport|iport|iaddr\n1|UPNP|IPv4|TCP|1|1|192.168.1.1\n");
	write_file(".filters", "LEASE-FILTERS 9\nmap|raddr\n");
	lease_files_ignore_checksum = 1;
	assert(load() == -1 && ngot == 0);
	lease_files_ignore_checksum = 0;
	assert(slurp(".mappings") == NULL && slurp(".filters") == NULL);
	bad = slurp(".filters.bad");
	assert(bad != NULL && strncmp(bad, "LEASE-FILTERS 9", 15) == 0);
	free(bad);
	bad = slurp(".mappings.bad");
	assert(bad != NULL);
	free(bad);
	unlink_file(".mappings.bad");
	unlink_file(".filters.bad");
}

/* .checksum has the size and CRC-32 of each file a save wrote; a file
 * changed after the save is not read, and the set goes aside */
static void
test_checksum(void)
{
	char * sum, * m;
	char line[64];

	lease_table_clear();
	outgoing_table_clear();
	remove_files();
	lease_table_link(add_row(30, MAP_KIND_NATPMP, AF_INET, IPPROTO_UDP, 43000,
	                         "::ffff:192.168.1.10", 80, NULL, 0, NULL, 0));
	now += LEASE_FILES_MAX_DELAY;
	poll_now(1);
	assert(lease_files_flush() == 0);
	sum = slurp(".checksum");
	m = slurp(".mappings");
	assert(sum != NULL && m != NULL);
	assert(strncmp(sum, "LEASE-CHECKSUM 1", 16) == 0);
	assert(strstr(sum, "\nfile|bytes|crc32\n") != NULL);
	snprintf(line, sizeof(line), "\nmappings|%lu|", (unsigned long)strlen(m));
	assert(strstr(sum, line) != NULL);
	assert(strstr(sum, "\nfilters|") != NULL && strstr(sum, "\noutgoing|") != NULL);
	free(sum);
	assert(load() == 1 && ngot == 1);
	/* one byte changed: the set goes aside, nothing is read */
	m[strlen(m) - 2] ^= 1;
	write_file(".mappings", m);
	free(m);
	assert(load() == -1 && ngot == 0);
	assert(slurp(".mappings") == NULL && slurp(".checksum") == NULL);
	m = slurp(".checksum.bad");
	assert(m != NULL);
	free(m);
	unlink_file(".mappings.bad");
	unlink_file(".filters.bad");
	unlink_file(".outgoing.bad");
	unlink_file(".outgoing.peers.bad");
	unlink_file(".checksum.bad");
	free_got();
	lease_table_clear();
}

/* a crash after the rename of .checksum, before that of .mappings: the old
 * .mappings matches its line of .checksum too, and is read */
static void
test_cut_save(void)
{
	char * old, * sum, * p;
	int n = 0;

	lease_table_clear();
	outgoing_table_clear();
	remove_files();
	lease_table_link(add_row(31, MAP_KIND_NATPMP, AF_INET, IPPROTO_UDP, 43001,
	                         "::ffff:192.168.1.10", 81, NULL, 0, NULL, 0));
	now += LEASE_FILES_MAX_DELAY;
	poll_now(1);
	assert(lease_files_flush() == 0);
	old = slurp(".mappings");
	assert(old != NULL);
	lease_table_link(add_row(32, MAP_KIND_NATPMP, AF_INET, IPPROTO_UDP, 43002,
	                         "::ffff:192.168.1.10", 82, NULL, 0, NULL, 0));
	now += LEASE_FILES_MAX_DELAY;
	assert(lease_files_flush() == 0);
	/* the .mappings before and after the save */
	sum = slurp(".checksum");
	assert(sum != NULL);
	for(p = sum; (p = strstr(p, "\nmappings|")) != NULL; p++)
		n++;
	assert(n == 2);
	free(sum);
	write_file(".mappings", old);
	free(old);
	assert(load() == 1 && ngot == 1 && got_id(31, NULL) != NULL);
	free_got();
	lease_table_clear();
	remove_files();
}

/* a .mappings by hand, with the clocks of a save in its header when boot
 * is not NULL */
static void
put_mappings(const char * boot, long long mono, long long unix_time, const char * rows)
{
	char text[1024];
	if(boot != NULL)
		snprintf(text, sizeof(text), "LEASE-MAPPINGS 1 last_id=9 boot_id=%s monotonic=%lld unix=%lld\n"
		         "id|kind|family|proto|eport|iport|iaddr|eaddr|nonce|expiry|filters|label\n%s",
		         boot, mono, unix_time, rows);
	else
		snprintf(text, sizeof(text), "LEASE-MAPPINGS 1\n"
		         "id|kind|family|proto|eport|iport|iaddr|eaddr|nonce|expiry|filters|label\n%s",
		         rows);
	write_file(".mappings", text);
}

/* a line of .mappings: UPnP IPv4 TCP at eport, to its expiry */
static const char *
row_line(unsigned short eport, long long expiry)
{
	static char line[4][128];
	static int i;
	i = (i + 1) % 4;
	snprintf(line[i], sizeof(line[i]), "%hu|UPNP|IPv4|TCP|%hu|%hu|192.168.1.20|NA|NA|%lld|0|NA\n",
	         eport, eport, eport, expiry);
	return line[i];
}

/* the row of a load at eport */
static struct lease_entry *
got_at(unsigned short eport)
{
	int i;
	for(i = 0; i < ngot; i++)
		if(got[i]->eport == eport)
			return got[i];
	return NULL;
}

/* the clocks in the header of .mappings: what a save writes, and the ways
 * a load reads the expiry */
static void
test_clock(void)
{
	char bootf[300], line[512], rows[512], * c;
	struct lease_entry * row;
	struct timeval tv;
	time_t t;

	snprintf(bootf, sizeof(bootf), "%s/boot_id", dir);
	lease_files_boot_id_path = bootf;
	{
		FILE * f = fopen(bootf, "w");
		assert(f != NULL);
		fputs("boot-A\n", f);
		fclose(f);
	}
	remove_files();
	lease_files_ignore_checksum = 1;

	/* a save writes the boot and both clocks */
	lease_table_clear();
	outgoing_table_clear();
	lease_table_link(add_row(0, MAP_KIND_UPNP, AF_INET, IPPROTO_TCP, 41000, "::ffff:192.168.1.20",
	                         41000, NULL, now + 3600, NULL, 0));
	now += LEASE_FILES_MAX_DELAY;
	t = time(NULL);
	assert(lease_files_flush() == 0);
	c = slurp(".mappings");
	assert(c != NULL);
	snprintf(line, sizeof(line), "LEASE-MAPPINGS 1 last_id=%llu boot_id=boot-A monotonic=%lld unix=",
	         lease_table_last_id(), (long long)now);
	assert(strncmp(c, line, strlen(line)) == 0);
	assert(atoll(c + strlen(line)) - (long long)t <= 1);
	free(c);
	lease_table_clear();

	/* the same boot: the expiry is on the monotonic clock of the save,
	 * even with the wall clock far behind it */
	t = time(NULL) + 100000;
	snprintf(rows, sizeof(rows), "%s%s", row_line(41000, t + 500), row_line(41001, t + 5));
	put_mappings("boot-A", now - 10, t, rows);
	assert(load() == 1);
	assert(ngot == 1);	/* 41001 expired 5 s after a save 10 s ago */
	assert(got_at(41000)->timestamp == now - 10 + 500);
	/* .outgoing.peers of an earlier save, before the wall clock stepped 100000 s
	 * on: its lines are read on its own clocks */
	write_file(".outgoing", "LEASE-OUTGOING 1 last_id=7\n"
	           "id|family|proto|iaddr|iport|eaddr|eport|nonce|peers|label\n"
	           "7|IPv4|TCP|192.168.1.13|5000|198.51.100.1|6000|ab0000000000000000000000|1|NA\n"
	           "8|IPv4|TCP|192.168.1.14|5000|198.51.100.1|6001|ab0000000000000000000000|2|NA\n");
	snprintf(line, sizeof(line),
	         "LEASE-OUTGOING-PEERS 1 last_id=8 monotonic=%lld unix=%lld\n"
	         "binding|raddr|rport|expiry\n"
	         "7|203.0.113.1|80|%lld\n"
	         "8|203.0.113.2|80|%lld\n",
	         (long long)now - 20, (long long)t - 100000, (long long)t - 100000 + 400,
	         (long long)t - 100000 + 400);
	write_file(".outgoing.peers", line);
	/* 8 counts 2 peers, .outgoing.peers has 1: of another save */
	assert(load() == 1 && ngot == 1 && ngot_peer == 1);
	assert(got_peer[0]->id == 7 && got_peer[0]->peers[0].timestamp == now - 20 + 400);
	unlink_file(".outgoing");
	unlink_file(".outgoing.peers");

	/* a new boot with the clock behind the save: the restore waits, and
	 * no save drops the rows of the files meanwhile. A row a client makes
	 * meanwhile keeps its port */
	{
		FILE * f = fopen(bootf, "w");
		assert(f != NULL);
		fputs("boot-B\n", f);
		fclose(f);
	}
	t = time(NULL) + 2;
	snprintf(rows, sizeof(rows), "%s%s", row_line(41000, t + 600), row_line(41002, t + 600));
	put_mappings("boot-A", now + 99999, t, rows);
	/* a filter of the files with uid 9 (of no row here) */
	write_file(".filters", "LEASE-FILTERS 1\nmap|raddr|uid\n99|NA|9\n");
	assert(load() == 1);
	assert(ngot == 0);
	/* a filter made meanwhile gets no uid of the files */
	assert(lease_table_new_uid() > 9);
	unlink_file(".filters");
	/* on the WAN address; the row of the file has none (NA) */
	lease_table_link(add_row(0, MAP_KIND_NATPMP, AF_INET, IPPROTO_TCP, 41002, "::ffff:192.168.1.21",
	                         41002, "::ffff:198.51.100.1", 0, NULL, 0));
	tv.tv_sec = 60;
	tv.tv_usec = 0;
	lease_files_poll(1, &tv);
	assert(tv.tv_sec == 5);	/* checks the clock again in 5 s */
	assert(lease_files_flush() == 0);
	c = slurp(".mappings");
	assert(strstr(c, "|41000|") != NULL && strstr(c, "|NAT-PMP|") == NULL);
	free(c);
	while(time(NULL) < t)
		usleep(100000);
	tv.tv_sec = 60;
	lease_files_poll(1, &tv);
	assert(ngot == 1 && got_at(41002) == NULL);
	assert(got_at(41000)->timestamp >= now + 598 && got_at(41000)->timestamp <= now + 600);
	lease_table_clear();

	/* the clock is never set: after the wait, each row comes back with
	 * the lease it had left at the save */
	t = time(NULL) + 100000;
	put_mappings("boot-A", now + 99999, t, row_line(41000, t + 600));
	assert(load() == 1 && ngot == 0);
	now += 299;
	tv.tv_sec = 60;
	lease_files_poll(1, &tv);
	assert(ngot == 0 && tv.tv_sec == 5);
	now += 1;
	tv.tv_sec = 60;
	lease_files_poll(1, &tv);
	assert(ngot == 1 && got_at(41000)->timestamp == now + 600);
	/* and the saves go on */
	row = add_row(0, MAP_KIND_NATPMP, AF_INET, IPPROTO_TCP, 41003, "::ffff:192.168.1.21",
	              41003, NULL, now + 60, NULL, 0);
	lease_table_link(row);
	assert(lease_files_flush() == 0);
	c = slurp(".mappings");
	assert(strstr(c, "|NAT-PMP|") != NULL);
	free(c);
	lease_table_clear();

	/* lease_file_restore=boot: the same boot only */
	lease_file_restore = LEASE_RESTORE_BOOT;
	{
		FILE * f = fopen(bootf, "w");
		assert(f != NULL);
		fputs("boot-B\n", f);
		fclose(f);
	}
	put_mappings("boot-B", now, time(NULL), row_line(41000, 0));
	assert(load() == 1 && ngot == 1);
	put_mappings("boot-A", now, time(NULL), row_line(41000, 0));
	assert(load() == 2 && ngot == 0);
	put_mappings(NULL, 0, 0, row_line(41000, 0));
	assert(load() == 2 && ngot == 0);	/* the boot of the save is not known */

	/* no boot id (BSD): the clocks tell. Both moved alike: the same boot,
	 * read on the monotonic clock */
	lease_files_boot_id_path = "/nonexistent";
	put_mappings("NA", now - 100, time(NULL) - 100, row_line(41000, time(NULL) + 1000));
	assert(load() == 1 && ngot == 1 && got_at(41000)->timestamp == now + 1000);
	/* the wall clock moved 1000 s more than the monotonic one */
	put_mappings("NA", now - 100, time(NULL) - 1100, row_line(41000, 0));
	assert(load() == 2 && ngot == 0);
	/* the monotonic clock went back */
	put_mappings("NA", now + 100, time(NULL) + 100, row_line(41000, 0));
	assert(load() == 2 && ngot == 0);
	/* lease_file_restore=no: never */
	lease_file_restore = LEASE_RESTORE_NO;
	put_mappings("NA", now - 100, time(NULL) - 100, row_line(41000, 0));
	assert(load() == 2 && ngot == 0);
	lease_file_restore = LEASE_RESTORE_YES;

	/* no clocks in the header: unix time */
	put_mappings(NULL, 0, 0, row_line(41000, 0));
	assert(load() == 1 && ngot == 1);
	free_got();
	lease_table_clear();
	unlink(bootf);
	lease_files_ignore_checksum = 0;
	remove_files();
}

/* a temporary file of a save cut short goes at startup; another file
 * stays */
static void
test_temp_files(void)
{
	char * s;
	write_file(".mappings.tmp.AbC123", "x");
	write_file(".mappings.tmp.toolong1", "y");
	lease_files_reserve_ids();
	assert(slurp(".mappings.tmp.AbC123") == NULL);
	s = slurp(".mappings.tmp.toolong1");
	assert(s != NULL);
	free(s);
	unlink_file(".mappings.tmp.toolong1");
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
	test_round_trip();
	test_hand_file();
	test_bad_files();
	test_checksum();
	test_cut_save();
	test_clock();
	test_temp_files();
	remove_files();
	rmdir(dir);
	printf("testleasefiles: OK\n");
	return 0;
}

#endif /* ENABLE_LEASEFILE */
