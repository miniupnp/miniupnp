/* The mappings of all the protocols, in memory.
 * One row per mapping or pinhole, found by its external key, or by its
 * UniqueID for a UPnP pinhole. */
#ifndef LEASE_TABLE_H_INCLUDED
#define LEASE_TABLE_H_INCLUDED

#include <time.h>
#include <netinet/in.h>

enum lease_kind { LEASE_PCP_MAP, LEASE_NATPMP, LEASE_UPNP };

#define LEASE_NONCE_LEN	12

struct lease_remote {
	struct in6_addr raddr;
	unsigned short rport;	/* 0 : any */
	/* later : struct lease_entry * map;	its row in Mappings */
};

struct lease_entry {
	struct lease_entry * ext_next;
	struct lease_entry * uid_next;
	unsigned char kind;
	unsigned char family;	/* AF_INET, AF_INET6 */
	unsigned char proto;
	unsigned short eport;
	unsigned short iport;
	struct in6_addr iaddr;	/* IPv4 as ::ffff:a.b.c.d */
	struct in6_addr eaddr;	/* :: : the default address of the interface */
	unsigned char nonce[LEASE_NONCE_LEN];	/* UPnP : the UniqueID in the first two */
	time_t expiry;
	char * label;		/* the rule description */
	struct lease_remote * remote;
	/* Fields a row gets later:
	 * time_t since;			first created, a renewal keeps it
	 * char * ifname;			the external interface
	 * unsigned char prefer_failure;	from the PCP request
	 * struct lease_filter * filters;	the FILTER peers of a PCP MAP
	 * #ifdef USE_NFTABLES
	 * unsigned long long rule_handle;	of the rule, 0 : unknown
	 * unsigned long long filter_handle;	of its forward rule, 0 : unknown
	 * #endif
	 * with USE_NFTABLES, lease_table.c must then include config.h */
};

/* the UniqueID of a UPnP pinhole, else 0. PCP has only its nonce */
static inline unsigned short
lease_uid(const struct lease_entry * e)
{
	return e->kind == LEASE_UPNP ? (unsigned short)(e->nonce[0] << 8 | e->nonce[1]) : 0;
}

static inline void
lease_set_uid(struct lease_entry * e, unsigned short uid)
{
	e->nonce[0] = (unsigned char)(uid >> 8);
	e->nonce[1] = (unsigned char)uid;
}

/* the key fields of e (kind, family, proto, ports, addresses, nonce) are
 * copied, the row is added to the indexes. raddr != NULL adds its remote.
 * NULL if there is no memory or the external key is in use */
struct lease_entry *
lease_table_add(const struct lease_entry * e, const struct in6_addr * raddr,
                unsigned short rport);

/* removes the row from the indexes and frees it and its remote */
void lease_table_remove(struct lease_entry * e);

/* raddr NULL : the row without a remote */
struct lease_entry *
lease_table_find_external(int proto, int family, const struct in6_addr * eaddr,
                          unsigned short eport, const struct in6_addr * raddr,
                          unsigned short rport);

/* the mapping of an external port, with or without a remote */
struct lease_entry *
lease_table_find_mapping(int proto, int family, const struct in6_addr * eaddr,
                         unsigned short eport);

struct lease_entry * lease_table_find_uid(unsigned short uid);

/* calls cb for every row. cb may not change the table */
void lease_table_foreach(void (*cb)(struct lease_entry *, void *), void * arg);

unsigned int lease_table_count(void);
void lease_table_clear(void);

#endif
