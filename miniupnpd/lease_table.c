/* The rows and indexes of the mapping table. See lease_table.h. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <syslog.h>

#include "lease_table.h"

/* the size of an index at the first row */
#define MIN_BUCKETS	1024u

/* A hash table with chains: a bucket is the first row of its chain, and the
 * rows link to the next one. */
struct index {
	struct lease_entry ** buckets;
	unsigned int size;	/* a power of 2, so hash & (size - 1) is the bucket */
};

/* The indexes are empty until the first row: see ready(). They grow with the
 * rows. */
static struct index ext_index, int_index;
static unsigned int count = 0;	/* the number of rows */
static unsigned int filter_count = 0;	/* the filters of the linked rows */
static unsigned long long last_id = 0;	/* the highest id given or linked */
static unsigned long changes[LEASE_T_PARTS];	/* see lease_table_changes() */

/* the list of the port mappings: see lease_table.h */
static struct lease_entry * port_head, * port_tail;
static unsigned int port_count = 0;	/* the rows on the list */
/* the row of index port_cursor_index. An add goes at the end and does not
 * move it. A remove clears it */
static struct lease_entry * port_cursor;
static unsigned int port_cursor_index;

/* The UID index: uid -> filter, in pages of 256 uids. A page is there once
 * one of its uids is, so a table of a few uids costs a few pages. */
#define UID_PAGES	256
#define UID_PAGE_SIZE	256
static struct map_filter ** uid_pages[UID_PAGES];
static unsigned int uid_count;	/* the uids in the index */
static unsigned short last_uid;	/* the last uid given or reserved */

/* the uids 1 to UID_MAX */
#define UID_MAX	65534

/* FNV-1a: add len bytes to the hash h */
static unsigned int
hash_bytes(unsigned int h, const void * data, size_t len)
{
	const unsigned char * p = data;
	while(len-- > 0)
		h = (h ^ *p++) * 16777619u;
	return h;
}

#define HASH_INIT	2166136261u

/* The hash of the external index. The protocol is left out, so TCP and UDP of
 * a port are in one chain, for lease_table_port_used_by_other(). The chain
 * walk compares the rest of the key. */
static unsigned int
ext_hash_key(int family, const struct in6_addr * eaddr, unsigned short eport)
{
	unsigned char head = (unsigned char)family;
	unsigned int h = hash_bytes(HASH_INIT, &head, sizeof(head));
	h = hash_bytes(h, eaddr, sizeof(*eaddr));
	return hash_bytes(h, &eport, sizeof(eport));
}

/* the hash of the internal index: all the rows of one internal endpoint */
static unsigned int
int_hash_key(int proto, int family, const struct in6_addr * iaddr,
             unsigned short iport)
{
	unsigned char head[2];
	unsigned int h;
	head[0] = (unsigned char)proto;
	head[1] = (unsigned char)family;
	h = hash_bytes(HASH_INIT, head, sizeof(head));
	h = hash_bytes(h, iaddr, sizeof(*iaddr));
	return hash_bytes(h, &iport, sizeof(iport));
}

static unsigned int
ext_hash(const struct lease_entry * e)
{
	return ext_hash_key(e->family, &e->eaddr, e->eport);
}

static unsigned int
int_hash(const struct lease_entry * e)
{
	return int_hash_key(e->proto, e->family, &e->iaddr, e->iport);
}

/* an empty index of size buckets. 0, or -1 if there is no memory */
static int
index_init(struct index * x, unsigned int size)
{
	x->buckets = calloc(size, sizeof(*x->buckets));
	if(x->buckets == NULL)
		return -1;
	x->size = size;
	return 0;
}

/* Double the external and internal indexes and move the rows over, which keeps
 * their chains short. On failure the old ones stay: only the chains get longer. */
static void
grow(void)
{
	struct index ext2, int2;
	unsigned int size = ext_index.size * 2, i;
	if(index_init(&ext2, size) < 0) {
		syslog(LOG_INFO, "lease table: no memory to grow to %u buckets", size);
		return;
	}
	if(index_init(&int2, size) < 0) {
		free(ext2.buckets);
		syslog(LOG_INFO, "lease table: no memory to grow to %u buckets", size);
		return;
	}
	for(i = 0; i < ext_index.size; i++) {
		struct lease_entry * e = ext_index.buckets[i], * next;
		for(; e != NULL; e = next) {
			unsigned int b = ext_hash(e) & (size - 1);
			next = e->ext_next;
			e->ext_next = ext2.buckets[b];
			ext2.buckets[b] = e;
		}
	}
	for(i = 0; i < int_index.size; i++) {
		struct lease_entry * e = int_index.buckets[i], * next;
		for(; e != NULL; e = next) {
			unsigned int b = int_hash(e) & (size - 1);
			next = e->int_next;
			e->int_next = int2.buckets[b];
			int2.buckets[b] = e;
		}
	}
	free(ext_index.buckets);
	free(int_index.buckets);
	ext_index = ext2;
	int_index = int2;
	syslog(LOG_INFO, "lease table: %u buckets for %u rows", size, count);
}

/* Set up the indexes at the first row. A daemon with no mappings then pays
 * nothing for them. 0, or -1 if there is no memory */
static int
ready(void)
{
	if(ext_index.buckets != NULL)
		return 0;
	if(index_init(&ext_index, MIN_BUCKETS) < 0)
		return -1;
	if(index_init(&int_index, MIN_BUCKETS) < 0) {
		free(ext_index.buckets);
		memset(&ext_index, 0, sizeof(ext_index));
		return -1;
	}
	return 0;
}

struct lease_entry *
lease_table_find_mapping(int proto, int family, const struct in6_addr * eaddr,
                         unsigned short eport)
{
	struct lease_entry * e;
	if(ext_index.buckets == NULL)
		return NULL;
	e = ext_index.buckets[ext_hash_key(family, eaddr, eport) & (ext_index.size - 1)];
	for(; e != NULL; e = e->ext_next) {
		if(e->proto == proto && e->family == family &&
		   e->eport == eport &&
		   memcmp(&e->eaddr, eaddr, sizeof(*eaddr)) == 0)
			return e;
	}
	return NULL;
}

struct lease_entry *
lease_table_port_used_by_other(int family, const struct in6_addr * eaddr,
                               unsigned short eport, const struct in6_addr * iaddr)
{
	struct lease_entry * e;
	if(ext_index.buckets == NULL)
		return NULL;
	e = ext_index.buckets[ext_hash_key(family, eaddr, eport) & (ext_index.size - 1)];
	for(; e != NULL; e = e->ext_next) {
		if(e->family == family && e->eport == eport &&
		   memcmp(&e->eaddr, eaddr, sizeof(*eaddr)) == 0 &&
		   memcmp(&e->iaddr, iaddr, sizeof(*iaddr)) != 0)
			return e;
	}
	return NULL;
}

struct lease_entry *
lease_table_next_internal(const struct lease_entry * prev, int proto, int family,
                          const struct in6_addr * iaddr, unsigned short iport)
{
	struct lease_entry * e;
	if(int_index.buckets == NULL)
		return NULL;
	e = prev ? prev->int_next
	         : int_index.buckets[int_hash_key(proto, family, iaddr, iport) &
	                             (int_index.size - 1)];
	for(; e != NULL; e = e->int_next) {
		if(e->proto == proto && e->family == family &&
		   e->iport == iport &&
		   memcmp(&e->iaddr, iaddr, sizeof(*iaddr)) == 0)
			return e;
	}
	return NULL;
}

struct lease_entry *
lease_table_find_entry(int proto, int family, const struct in6_addr * iaddr,
                       unsigned short iport, unsigned short eport)
{
	struct lease_entry * e = NULL;
	while((e = lease_table_next_internal(e, proto, family, iaddr, iport)) != NULL) {
		if(e->eport == eport)
			return e;
	}
	return NULL;
}

/* The slot of a uid, or NULL if its page is not there and make is 0. With
 * make, the page is made; NULL then if there is no memory. */
static struct map_filter **
uid_slot(unsigned short uid, int make)
{
	struct map_filter *** page = &uid_pages[uid / UID_PAGE_SIZE];
	if(*page == NULL) {
		if(!make)
			return NULL;
		*page = calloc(UID_PAGE_SIZE, sizeof(**page));
		if(*page == NULL)
			return NULL;
	}
	return &(*page)[uid % UID_PAGE_SIZE];
}

/* Put a filter with a uid in the UID index. On no memory the filter stays out
 * of it: a lookup by its uid then fails, and nothing else. */
static void
uid_link(struct map_filter * f)
{
	struct map_filter ** slot = uid_slot(f->uid, 1);
	if(slot == NULL) {
		syslog(LOG_INFO, "lease table: no memory for the uid %hu", f->uid);
		return;
	}
	if(*slot == NULL)
		uid_count++;
	*slot = f;
}

/* Take the uid of a filter out of the UID index. */
static void
uid_unlink(const struct map_filter * f)
{
	struct map_filter ** slot = uid_slot(f->uid, 0);
	if(slot != NULL && *slot == f) {
		*slot = NULL;
		uid_count--;
	}
}

/* The filters of a linked row moved: point their uids at them again. */
static void
uid_repoint(struct lease_entry * e)
{
	int i;
	struct map_filter ** slot;
	if(!e->linked)
		return;
	for(i = 0; i < e->nfilters; i++) {
		if(e->filters[i].uid == 0)
			continue;
		slot = uid_slot(e->filters[i].uid, 0);
		if(slot != NULL)
			*slot = &e->filters[i];
	}
}

struct map_filter *
lease_table_find_uid(unsigned short uid)
{
	struct map_filter ** slot;
	if(uid == 0)
		return NULL;
	slot = uid_slot(uid, 0);
	return slot != NULL ? *slot : NULL;
}

/* Look for a free uid from the one after the last given. With every uid in
 * use, there is no need to look. */
unsigned short
lease_table_new_uid(void)
{
	unsigned int n;
	if(uid_count >= UID_MAX)
		return 0;
	for(n = 0; n < UID_MAX; n++) {
		last_uid = (unsigned short)(last_uid >= UID_MAX ? 1 : last_uid + 1);
		if(lease_table_find_uid(last_uid) == NULL)
			return last_uid;
	}
	return 0;
}

void
lease_table_reserve_uids(unsigned short max)
{
	if(max > last_uid && max <= UID_MAX)
		last_uid = max;
}

void
lease_filter_set_uid(struct map_filter * f, unsigned short uid)
{
	struct lease_entry * e = f->map;
	if(e->linked && f->uid != 0)
		uid_unlink(f);
	f->uid = uid;
	if(e->linked) {
		uid_link(f);
		lease_table_touch(e);
	}
}

/* Give the filter array of e room for n filters. 0, or -1 if there is no
 * memory, and the array then stays as it was. */
static int
filters_room(struct lease_entry * e, int n)
{
	struct map_filter * a;
	int i;
	if(n <= e->filters_alloc)
		return 0;
	a = realloc(e->filters, (size_t)n * sizeof(*a));
	if(a == NULL)
		return -1;
	e->filters = a;
	e->filters_alloc = n;
	for(i = 0; i < e->nfilters; i++)
		a[i].map = e;
	uid_repoint(e);
	return 0;
}

struct map_filter *
lease_filter_add(struct lease_entry * e, const struct map_filter * f)
{
	struct map_filter * n;
	if(filters_room(e, e->nfilters + 1) < 0) {
		syslog(LOG_INFO, "lease table: no memory for a filter of port %hu",
		       e->eport);
		return NULL;
	}
	n = &e->filters[e->nfilters++];
	*n = *f;
	n->map = e;
	if(e->linked) {
		if(n->uid != 0)
			uid_link(n);
		filter_count++;
		lease_table_touch(e);
	}
	return n;
}

void
lease_filter_drop(struct lease_entry * e, struct map_filter * f)
{
	int i = (int)(f - e->filters);
	if(e->linked) {
		if(f->uid != 0)
			uid_unlink(f);
		filter_count--;
		lease_table_touch(e);
	}
	memmove(f, f + 1, (size_t)(e->nfilters - i - 1) * sizeof(*f));
	e->nfilters--;
	uid_repoint(e);
}

struct map_filter *
lease_filter_find(const struct lease_entry * e, const struct in6_addr * raddr,
                  unsigned char prefix, unsigned short rport)
{
	int i;
	for(i = 0; i < e->nfilters; i++) {
		struct map_filter * f = &e->filters[i];
		if(f->rport == rport && f->prefix == prefix &&
		   memcmp(&f->raddr, raddr, sizeof(*raddr)) == 0)
			return f;
	}
	return NULL;
}

/* 1 if the row belongs on the port list */
static int
is_port_mapping(const struct lease_entry * e)
{
	return e->family == AF_INET;
}

/* a new row goes at the end: the list is in the order of the adds */
static void
port_list_add(struct lease_entry * e)
{
	e->port_next = NULL;
	e->port_prev = port_tail;
	if(port_tail != NULL)
		port_tail->port_next = e;
	else
		port_head = e;
	port_tail = e;
	port_count++;
}

/* put e on the list after "after", or first with NULL */
static void
port_list_insert_after(struct lease_entry * e, struct lease_entry * after)
{
	e->port_prev = after;
	e->port_next = after != NULL ? after->port_next : port_head;
	if(e->port_next != NULL)
		e->port_next->port_prev = e;
	else
		port_tail = e;
	if(after != NULL)
		after->port_next = e;
	else
		port_head = e;
	port_count++;
	port_cursor = NULL;
}

/* The rows after e move up one place, so the remembered place is cleared. */
static void
port_list_remove(struct lease_entry * e)
{
	if(e->port_prev != NULL)
		e->port_prev->port_next = e->port_next;
	else
		port_head = e->port_next;
	if(e->port_next != NULL)
		e->port_next->port_prev = e->port_prev;
	else
		port_tail = e->port_prev;
	port_count--;
	port_cursor = NULL;
}

struct lease_entry *
lease_table_port_at(unsigned int index)
{
	struct lease_entry * e = port_head;
	unsigned int i = 0;

	if(index >= port_count)
		return NULL;
	if(port_cursor != NULL && port_cursor_index <= index) {
		e = port_cursor;
		i = port_cursor_index;
	}
	for(; i < index; i++)
		e = e->port_next;
	port_cursor = e;
	port_cursor_index = index;
	return e;
}

unsigned int
lease_table_port_count(void)
{
	return port_count;
}

struct lease_entry *
lease_table_next_port(const struct lease_entry * prev)
{
	return prev != NULL ? prev->port_next : port_head;
}

struct lease_entry *
lease_table_new(int nfilters)
{
	struct lease_entry * e;
	int i;

	if(ready() < 0)
		goto fail;
	e = calloc(1, sizeof(*e));
	if(e == NULL)
		goto fail;
	if(nfilters > 0) {
		e->filters = calloc((size_t)nfilters, sizeof(*e->filters));
		if(e->filters == NULL) {
			free(e);
			goto fail;
		}
		e->filters_alloc = e->nfilters = nfilters;
		for(i = 0; i < nfilters; i++)
			e->filters[i].map = e;
	}
	e->row = 1;
	return e;
fail:
	syslog(LOG_INFO, "lease table: no memory for a row");
	return NULL;
}

void
lease_table_free(struct lease_entry * e)
{
	free(e->filters);
	free(e);
}

struct lease_entry *
lease_table_copy(const struct lease_entry * r)
{
	struct lease_entry * e = lease_table_new(r->nfilters);
	int i;

	if(e == NULL)
		return NULL;
	e->kind = r->kind;
	e->flags = r->flags;
	e->family = r->family;
	e->proto = r->proto;
	memcpy(e->nonce, r->nonce, sizeof(e->nonce));
	e->iaddr = r->iaddr;
	e->eaddr = r->eaddr;
	e->iport = r->iport;
	e->eport = r->eport;
	e->timestamp = r->timestamp;
	e->label = r->label;
	for(i = 0; i < r->nfilters; i++) {
		e->filters[i] = r->filters[i];
		e->filters[i].map = e;
	}
	return e;
}

void
lease_table_link(struct lease_entry * e)
{
	unsigned int b;
	int i;

	if(count >= ext_index.size)
		grow();
	b = ext_hash(e) & (ext_index.size - 1);
	e->ext_next = ext_index.buckets[b];
	ext_index.buckets[b] = e;
	b = int_hash(e) & (int_index.size - 1);
	e->int_next = int_index.buckets[b];
	int_index.buckets[b] = e;
	/* the label was the caller's: the row keeps a copy */
	if(e->label != NULL && (e->label = strdup(e->label)) == NULL)
		syslog(LOG_INFO, "lease table: no memory for the label of port %hu", e->eport);
	e->linked = 1;
	for(i = 0; i < e->nfilters; i++) {
		e->filters[i].map = e;
		if(e->filters[i].uid != 0)
			uid_link(&e->filters[i]);
	}
	if(is_port_mapping(e))
		port_list_add(e);
	if(e->id == 0)
		e->id = ++last_id;
	else if(e->id > last_id)
		last_id = e->id;
	filter_count += (unsigned int)e->nfilters;
	count++;
	lease_table_touch(e);
}

/* Take a row out of the indexes and the port list. */
static void
unlink_row(struct lease_entry * e)
{
	struct lease_entry ** p;
	int i;

	p = &ext_index.buckets[ext_hash(e) & (ext_index.size - 1)];
	while(*p != e)
		p = &(*p)->ext_next;
	*p = e->ext_next;
	p = &int_index.buckets[int_hash(e) & (int_index.size - 1)];
	while(*p != e)
		p = &(*p)->int_next;
	*p = e->int_next;
	for(i = 0; i < e->nfilters; i++) {
		if(e->filters[i].uid != 0)
			uid_unlink(&e->filters[i]);
	}
	if(is_port_mapping(e))
		port_list_remove(e);
	e->linked = 0;
	lease_table_touch(e);
	filter_count -= (unsigned int)e->nfilters;
	count--;
}

void
lease_table_link_in_place(struct lease_entry * e, struct lease_entry * old)
{
	int keep = is_port_mapping(old) && is_port_mapping(e);
	struct lease_entry * after = keep ? old->port_prev : NULL;

	if(e->id == 0)
		e->id = old->id;
	lease_table_remove(old);
	lease_table_link(e);
	if(keep) {
		port_list_remove(e);
		port_list_insert_after(e, after);
	}
}

void
lease_table_remove(struct lease_entry * e)
{
	unlink_row(e);
	free((char *)e->label);
	lease_table_free(e);
}

void
lease_table_reserve_ids(unsigned long long max)
{
	if(max > last_id)
		last_id = max;
}

unsigned long long
lease_table_last_id(void)
{
	return last_id;
}

int
lease_table_set_label(struct lease_entry * e, const char * label)
{
	char * copy = NULL;
	if(label != NULL && (copy = strdup(label)) == NULL)
		return -1;
	free((char *)e->label);
	e->label = copy;
	if(e->linked)
		changes[LEASE_T_MAPPINGS]++;	/* no filter line holds it */
	return 0;
}

void
lease_table_set_expiry(struct lease_entry * e, unsigned int timestamp)
{
	e->timestamp = timestamp;
	if(e->linked)
		changes[LEASE_T_MAPPINGS]++;	/* no filter line holds it */
}

unsigned long
lease_table_changes(enum lease_table_part part)
{
	return changes[part];
}

/* Count a change of a row, in each table it has a line in. */
void
lease_table_touch(const struct lease_entry * e)
{
	changes[LEASE_T_MAPPINGS]++;
	if(e->nfilters > 0)
		changes[LEASE_T_FILTERS]++;
}

int
lease_table_same_owner(const struct lease_entry * a, const struct lease_entry * b)
{
	/* UPnP and NAT-PMP have a zero nonce: comparing it is the same as
	 * comparing the parts the kind has */
	return a->kind == b->kind && a->family == b->family &&
	       a->proto == b->proto && a->iport == b->iport &&
	       memcmp(&a->iaddr, &b->iaddr, sizeof(a->iaddr)) == 0 &&
	       memcmp(a->nonce, b->nonce, MAP_NONCE_LEN) == 0;
}

/* Call cb for every row, by walking the external index. */
void
lease_table_foreach(void (*cb)(struct lease_entry *, void *), void * arg)
{
	unsigned int i;
	struct lease_entry * e, * next;
	for(i = 0; i < ext_index.size; i++) {
		/* the next row first: cb may remove e */
		for(e = ext_index.buckets[i]; e != NULL; e = next) {
			next = e->ext_next;
			cb(e, arg);
		}
	}
}

unsigned int
lease_table_count(void)
{
	return count;
}

unsigned int
lease_table_filter_count(void)
{
	return filter_count;
}

void
lease_table_clear(void)
{
	unsigned int i;

	syslog(LOG_DEBUG, "lease table: clear %u rows", count);
	for(i = 0; i < ext_index.size; i++) {
		while(ext_index.buckets[i] != NULL)
			lease_table_remove(ext_index.buckets[i]);
	}
	free(ext_index.buckets);
	free(int_index.buckets);
	memset(&ext_index, 0, sizeof(ext_index));
	memset(&int_index, 0, sizeof(int_index));
	for(i = 0; i < UID_PAGES; i++) {
		free(uid_pages[i]);
		uid_pages[i] = NULL;
	}
	uid_count = 0;
}

/* the name of a protocol, for the dump. Not proto_itoa(): the table links
 * alone in testleasetable */
static const char *
proto_name(int proto)
{
	switch(proto) {
	case IPPROTO_TCP:	return "TCP";
	case IPPROTO_UDP:	return "UDP";
#ifdef IPPROTO_UDPLITE
	case IPPROTO_UDPLITE:	return "UDPLITE";
#endif
	default:		return "?";
	}
}

/* one row and its filters */
static void
dump_row(struct lease_entry * e, void * arg)
{
	FILE * f = arg;
	char iaddr[INET6_ADDRSTRLEN], eaddr[INET6_ADDRSTRLEN], raddr[INET6_ADDRSTRLEN];
	char nonce[2 * MAP_NONCE_LEN + 1];
	int i;

	if(map_ntop(e->family, &e->iaddr, iaddr, sizeof(iaddr)) == NULL)
		iaddr[0] = '\0';
	if(map_ntop(e->family, &e->eaddr, eaddr, sizeof(eaddr)) == NULL)
		eaddr[0] = '\0';
	fprintf(f, "id=%llu %s %s %s [%s]:%hu <- [%s]:%hu expiry=%u",
	        e->id, map_kind_name(e->kind), map_family_name(e->family),
	        proto_name(e->proto), iaddr, e->iport, eaddr, e->eport,
	        e->timestamp);
	if(e->kind == MAP_KIND_PCP)
		fprintf(f, " nonce=%s", map_nonce_ntop(e->nonce, nonce));
	if(e->fw_partial)
		fprintf(f, " fw_partial");
	if(e->retry != 0)
		fprintf(f, " retry=%u", e->retry);
	if(e->label != NULL)
		fprintf(f, " label=\"%s\"", e->label);
	fputc('\n', f);
	for(i = 0; i < e->nfilters; i++) {
		const struct map_filter * mf = &e->filters[i];
		if(inet_ntop(AF_INET6, &mf->raddr, raddr, sizeof(raddr)) == NULL)
			raddr[0] = '\0';
		fprintf(f, "\tfilter [%s]/%u:%hu uid=%hu\n",
		        raddr, mf->prefix, mf->rport, mf->uid);
	}
}

/* the IPv6 maps: the port list has the IPv4 ones */
static void
dump_row6(struct lease_entry * e, void * arg)
{
	if(!is_port_mapping(e))
		dump_row(e, arg);
}

void
lease_table_dump(FILE * f)
{
	struct lease_entry * e;

	fprintf(f, "# lease table: %u rows, %u port mappings, %u filters, %u uids, last id %llu\n",
	        count, port_count, filter_count, uid_count, last_id);
	for(e = port_head; e != NULL; e = e->port_next)
		dump_row(e, f);
	lease_table_foreach(dump_row6, f);
}
