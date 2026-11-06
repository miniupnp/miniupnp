/* The rows and hash indexes of the mapping table. See lease_table.h. */
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "lease_table.h"

/* the size of an index at the first row */
#define MIN_BUCKETS	1024u

/* A hash table with chains: a bucket is the first row of its chain, and the
 * rows link to the next one. */
struct index {
	struct lease_entry ** buckets;
	unsigned int size;	/* a power of 2, so hash & (size - 1) is the bucket */
};

/* Both indexes are empty until the first row: see ready(). The external index
 * grows with the rows, and the UID index keeps its size: a UniqueID is 16 bits,
 * so its chains stay short. */
static struct index ext_index, uid_index;
static unsigned int count = 0;	/* the number of rows */

/* ::, the eaddr of an IPv4 row */
static const struct in6_addr any_addr;

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

/* The hash of the external index. The protocol and the remote are left out, so
 * all the rows of one external port are in one chain: a lookup by port alone
 * can see them all. The chain walk compares the rest of the key. */
static unsigned int
ext_hash_key(int family, const struct in6_addr * eaddr, unsigned short eport)
{
	unsigned char head = (unsigned char)family;
	unsigned int h = hash_bytes(HASH_INIT, &head, sizeof(head));
	h = hash_bytes(h, eaddr, sizeof(*eaddr));
	return hash_bytes(h, &eport, sizeof(eport));
}

static unsigned int
ext_hash(const struct lease_entry * e)
{
	return ext_hash_key(e->family, &e->eaddr, e->eport);
}

static unsigned int
uid_hash(unsigned short uid)
{
	return hash_bytes(HASH_INIT, &uid, sizeof(uid));
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

/* Double the external index and move the rows over, which keeps its chains
 * short. On failure the old one stays: only the chains get longer. */
static void
grow(void)
{
	struct index ext2;
	unsigned int size = ext_index.size * 2, i;
	if(index_init(&ext2, size) < 0)
		return;
	for(i = 0; i < ext_index.size; i++) {
		struct lease_entry * e = ext_index.buckets[i], * next;
		for(; e != NULL; e = next) {
			unsigned int b = ext_hash(e) & (size - 1);
			next = e->ext_next;
			e->ext_next = ext2.buckets[b];
			ext2.buckets[b] = e;
		}
	}
	free(ext_index.buckets);
	ext_index = ext2;
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
	if(index_init(&uid_index, MIN_BUCKETS) < 0) {
		free(ext_index.buckets);
		memset(&ext_index, 0, sizeof(ext_index));
		return -1;
	}
	return 0;
}

/* 1 if the row has this exact remote. raddr NULL means a row with no remote */
static int
remote_matches(const struct lease_entry * e, const struct in6_addr * raddr,
               unsigned short rport)
{
	if(e->remote == NULL)
		return raddr == NULL;
	return raddr != NULL && e->remote->rport == rport &&
	       memcmp(&e->remote->raddr, raddr, sizeof(*raddr)) == 0;
}

struct lease_entry *
lease_table_find_external(int proto, int family, const struct in6_addr * eaddr,
                          unsigned short eport, const struct in6_addr * raddr,
                          unsigned short rport)
{
	struct lease_entry * e;
	if(ext_index.buckets == NULL)
		return NULL;
	if(eaddr == NULL)
		eaddr = &any_addr;
	e = ext_index.buckets[ext_hash_key(family, eaddr, eport) &
	                      (ext_index.size - 1)];
	for(; e != NULL; e = e->ext_next) {
		if(e->proto == proto && e->family == family && e->eport == eport &&
		   memcmp(&e->eaddr, eaddr, sizeof(*eaddr)) == 0 &&
		   remote_matches(e, raddr, rport))
			return e;
	}
	return NULL;
}

struct lease_entry *
lease_table_find_mapping(int proto, int family, const struct in6_addr * eaddr,
                         unsigned short eport)
{
	struct lease_entry * e;
	if(ext_index.buckets == NULL)
		return NULL;
	if(eaddr == NULL)
		eaddr = &any_addr;
	e = ext_index.buckets[ext_hash_key(family, eaddr, eport) &
	                      (ext_index.size - 1)];
	for(; e != NULL; e = e->ext_next) {
		if(e->proto == proto && e->family == family && e->eport == eport &&
		   memcmp(&e->eaddr, eaddr, sizeof(*eaddr)) == 0)
			return e;
	}
	return NULL;
}

struct lease_entry *
lease_table_find_uid(unsigned short uid)
{
	struct lease_entry * e;
	if(uid_index.buckets == NULL || uid == 0)
		return NULL;
	for(e = uid_index.buckets[uid_hash(uid) & (uid_index.size - 1)];
	    e != NULL; e = e->uid_next) {
		if(lease_uid(e) == uid)
			return e;
	}
	return NULL;
}

struct lease_entry *
lease_table_add(const struct lease_entry * src, const struct in6_addr * raddr,
                unsigned short rport)
{
	struct lease_entry * e;
	unsigned int b;

	if(ready() < 0)
		return NULL;
	if(lease_table_find_external(src->proto, src->family, &src->eaddr,
	                             src->eport, raddr, rport) != NULL)
		return NULL;
	if(count >= ext_index.size)
		grow();
	e = malloc(sizeof(*e));
	if(e == NULL)
		return NULL;
	*e = *src;
	e->ext_next = e->uid_next = NULL;
	e->label = NULL;
	e->remote = NULL;
	if(src->label != NULL && (e->label = strdup(src->label)) == NULL)
		goto fail;
	if(raddr != NULL) {
		e->remote = malloc(sizeof(*e->remote));
		if(e->remote == NULL)
			goto fail;
		e->remote->raddr = *raddr;
		e->remote->rport = rport;
	}
	b = ext_hash(e) & (ext_index.size - 1);
	e->ext_next = ext_index.buckets[b];
	ext_index.buckets[b] = e;
	if(lease_uid(e) != 0) {
		b = uid_hash(lease_uid(e)) & (uid_index.size - 1);
		e->uid_next = uid_index.buckets[b];
		uid_index.buckets[b] = e;
	}
	count++;
	return e;
fail:
	free(e->label);
	free(e);
	return NULL;
}

void
lease_table_remove(struct lease_entry * e)
{
	struct lease_entry ** p;

	p = &ext_index.buckets[ext_hash(e) & (ext_index.size - 1)];
	while(*p != e)
		p = &(*p)->ext_next;
	*p = e->ext_next;
	if(lease_uid(e) != 0) {
		p = &uid_index.buckets[uid_hash(lease_uid(e)) & (uid_index.size - 1)];
		while(*p != e)
			p = &(*p)->uid_next;
		*p = e->uid_next;
	}
	free(e->remote);
	free(e->label);
	free(e);
	count--;
}

void
lease_table_foreach(void (*cb)(struct lease_entry *, void *), void * arg)
{
	unsigned int i;
	struct lease_entry * e;
	for(i = 0; i < ext_index.size; i++) {
		for(e = ext_index.buckets[i]; e != NULL; e = e->ext_next)
			cb(e, arg);
	}
}

unsigned int
lease_table_count(void)
{
	return count;
}

void
lease_table_clear(void)
{
	unsigned int i;
	for(i = 0; i < ext_index.size; i++) {
		while(ext_index.buckets[i] != NULL)
			lease_table_remove(ext_index.buckets[i]);
	}
	free(ext_index.buckets);
	free(uid_index.buckets);
	memset(&ext_index, 0, sizeof(ext_index));
	memset(&uid_index, 0, sizeof(uid_index));
}
