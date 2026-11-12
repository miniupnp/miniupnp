/* The mapping table: the port mappings and pinholes of the daemon, in memory.
 *
 * UPnP, NAT-PMP and PCP all make the same kind of firewall rule, and they
 * compete for the same external ports. This table has one row for each of
 * those rules, whichever protocol made it. A row holds what the firewall
 * holds badly or not at all: the owner, the lifetime and the description.
 *
 * A row is a struct lease_entry, and it is one of these:
 * - An IPv4 port mapping: packets to eport go to iaddr:iport.
 * - An IPv6 pinhole: packets to iaddr:iport pass without translation, so
 *   eaddr equals iaddr and eport equals iport.
 * A row limited to one remote host also has a struct lease_remote.
 *
 * Two hash indexes find a row:
 * - The external index, by protocol, family, eaddr, eport and remote.
 * - The UID index, by the UniqueID of a UPnP pinhole.
 * The indexes hold no data. They link the rows through ext_next and uid_next.
 *
 * This file knows nothing of the protocols or the firewall. memmap.c fills
 * the rows from them. The daemon has one thread, so there are no locks. */
#ifndef LEASE_TABLE_H_INCLUDED
#define LEASE_TABLE_H_INCLUDED

#include <time.h>
#include <netinet/in.h>

/* The protocol which made a row. With the nonce it is the owner of the row. */
enum lease_kind { LEASE_PCP_MAP, LEASE_NATPMP, LEASE_UPNP };

/* the size of a PCP mapping nonce (RFC 6887 section 11.1) */
#define LEASE_NONCE_LEN	12

/* The remote host a row is limited to. Only a row with a limit has one, so a
 * plain mapping does not pay for these bytes. */
struct lease_remote {
	struct in6_addr raddr;	/* IPv4 as ::ffff:a.b.c.d */
	unsigned short rport;	/* 0 : any */
};

/* One port mapping or pinhole. lease_table_add() makes a row. */
struct lease_entry {
	struct lease_entry * ext_next;	/* the next row in its external bucket */
	struct lease_entry * uid_next;	/* the next row in its UID bucket */
	unsigned char kind;		/* enum lease_kind */
	unsigned char family;	/* AF_INET, AF_INET6 */
	unsigned char proto;	/* IPPROTO_TCP, IPPROTO_UDP, IPPROTO_UDPLITE */
	unsigned short eport;	/* host order. A pinhole: equals iport */
	unsigned short iport;	/* host order */
	struct in6_addr iaddr;	/* IPv4 as ::ffff:a.b.c.d */
	/* The external address. An IPv4 row has :: as the address is not stored yet:
	 * a daemon can have several, so :: does not name one. A pinhole has iaddr. */
	struct in6_addr eaddr;
	unsigned char nonce[LEASE_NONCE_LEN];	/* UPnP : the UniqueID in the first two */
	time_t expiry;		/* on the clock of upnp_time(). 0 : no expiry */
	char * label;		/* the rule description, owned by the row */
	struct lease_remote * remote;	/* NULL : any remote host. Owned by the row */
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

/* stores uid in the nonce bytes, which a UPnP row does not use for a nonce.
 * Set it before lease_table_add(), which indexes the uid */
static inline void
lease_set_uid(struct lease_entry * e, unsigned short uid)
{
	e->nonce[0] = (unsigned char)(uid >> 8);
	e->nonce[1] = (unsigned char)uid;
}

/* Add a row: a copy of e, with its label copied too, in all the indexes.
 * raddr != NULL limits the row to that remote. The row must not change its key
 * afterwards. Returns the row, or NULL if there is no memory or the external
 * key is in use. A row is one rule: lease_table_replace() replaces one. */
struct lease_entry *
lease_table_add(const struct lease_entry * e, const struct in6_addr * raddr,
                unsigned short rport);

/* Replace the row old by a copy of e, as lease_table_add() makes it. The key of
 * e may be that of old. Returns the new row, or NULL if there is no memory or
 * another row has the key of e: old then stays, and is still valid. */
struct lease_entry *
lease_table_replace(struct lease_entry * old, const struct lease_entry * e,
                    const struct in6_addr * raddr, unsigned short rport);

/* Take the row out of the indexes and free it, with its label and remote.
 * e is no longer valid afterwards. */
void lease_table_remove(struct lease_entry * e);

/* The exact row of an external key, or NULL. The remote is part of the key:
 * raddr NULL finds only a row with no remote, and raddr set finds only a row
 * limited to that remote. eaddr NULL means ::. Use this one to change or
 * remove a known rule. */
struct lease_entry *
lease_table_find_external(int proto, int family, const struct in6_addr * eaddr,
                          unsigned short eport, const struct in6_addr * raddr,
                          unsigned short rport);

/* A row on an external port, whatever its remote, or NULL. eaddr NULL means ::.
 * Use this one to ask "is this port mapped?". Rows of one port with different
 * remotes can exist, and this returns one of them. */
struct lease_entry *
lease_table_find_mapping(int proto, int family, const struct in6_addr * eaddr,
                         unsigned short eport);

/* The UPnP pinhole with this UniqueID, or NULL. A PCP row has no uid, and
 * uid 0 finds nothing. */
struct lease_entry * lease_table_find_uid(unsigned short uid);

/* Call cb for every row, in no set order. This visits all the rows, so it is
 * not for use on each request. cb may not add or remove a row: collect the
 * rows and remove them after the walk. */
void lease_table_foreach(void (*cb)(struct lease_entry *, void *), void * arg);

/* the number of rows */
unsigned int lease_table_count(void);

/* Remove all the rows and free the indexes. The next add sets them up again. */
void lease_table_clear(void);

#endif
