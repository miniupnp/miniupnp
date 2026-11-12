/* The layer between the protocols and the mapping table (lease_table.c).
 *
 * The code of the protocols works with strings and the arguments of a firewall
 * rule. The table works with rows. These functions turn the one into the other,
 * so upnpredirect.c and upnppinhole.c never touch a row. PCP and NAT-PMP call
 * those two files, so this covers all the protocols.
 *
 * A write goes to the firewall first, and here only if that worked. A row then
 * never stands for a rule which was refused.
 *
 * There are three adds, on either family. memmap_map() adds a mapping,
 * memmap_remote_peer() adds a mapping with its remote peer, and a filter has its
 * own add. iaddr gives the family. An IPv4 row is a port mapping, and an IPv6 row
 * is a pinhole: eport is iport, and the rule is that of a MAP without a remote
 * peer, or of a PEER with one. The other "peer" functions take either pinhole. */
#ifndef MEMMAP_H_INCLUDED
#define MEMMAP_H_INCLUDED

#include <sys/types.h>
#include <netinet/in.h>
#include "config.h"
#include "lease_table.h"

struct sockaddr;

/* Turn the text of an address into the form of the table: IPv4 a.b.c.d as
 * ::ffff:a.b.c.d with *family AF_INET, IPv6 as it is with AF_INET6. 0, or -1 if
 * s is no address. */
int memmap_pton(const char * s, int * family, struct in6_addr * a);

/* The text of an address of the table, in buf of len bytes. buf, or NULL if
 * it does not fit. */
const char * memmap_ntop(int family, const struct in6_addr * a, char * buf, size_t len);

/* A mapping as a protocol names it, without a remote. An IPv6 pinhole has no
 * translation: eaddr is iaddr and eport is iport. An IPv4 mapping has eaddr ::,
 * the one external address. */
struct memmap_key {
	int family;		/* AF_INET, AF_INET6 */
	int proto;
	struct in6_addr eaddr;
	unsigned short eport;
	struct in6_addr iaddr;	/* IPv4 as ::ffff:a.b.c.d */
	unsigned short iport;
};

/* The remote a mapping is limited to: a UPnP RemoteHost or a PCP PEER. It is a
 * part of the external key, so each remote is a row of its own. */
struct memmap_remote {
	struct in6_addr raddr;	/* IPv4 as ::ffff:a.b.c.d. :: : any host */
	unsigned short rport;	/* 0 : any */
};

/* The owner of a row: kind is an enum lease_kind. A PCP owner also has its
 * nonce, as on the wire. UPnP and NAT-PMP leave the nonce zero: any client of
 * the protocol may change their rows. */
struct memmap_owner {
	unsigned char kind;
	unsigned char nonce[LEASE_NONCE_LEN];
};

/* Fill a key. eaddr NULL : ::, the one external address of an IPv4 mapping.
 * An IPv6 key takes iaddr and iport as its external side. */
void memmap_key_init(struct memmap_key * k, int family, int proto,
                     const struct in6_addr * eaddr, unsigned short eport,
                     const struct in6_addr * iaddr, unsigned short iport);

/* Fill an owner. nonce NULL : zero. */
void memmap_owner_init(struct memmap_owner * o, int kind, const void * nonce);

/* The owner a description names: a PCP description ends in its nonce. See
 * mapping_owner_of(). */
void memmap_owner_from_desc(const char * desc, unsigned short eport, int proto,
                            struct memmap_owner * o);

/* The firewall added or changed a mapping with no remote peer: write its row.
 * A renewal, the same owner and rule, keeps the row and its place on the port
 * list, and gets the new expiry and description. Any other row on the port is
 * replaced. uid is the UniqueID of a UPnP pinhole, else 0. timestamp is the
 * expiry, 0 for none. */
void memmap_map(unsigned short uid, unsigned short eport, const char * iaddr,
                unsigned short iport, int proto, const char * desc,
                unsigned int timestamp);
/* The firewall removed an IPv4 mapping: remove its row, if it has one. */
void memmap_map_gone(unsigned short eport, int proto);
/* The mapping of an internal endpoint, with no read of the firewall. PCP and
 * NAT-PMP ask this to see if a client already has a mapping. Several owners
 * can map one endpoint: owner takes the row of that owner, and NULL the first
 * row of any. Returns 0 if found, else -1. desc and timestamp may be NULL. */
int memmap_find(int family, const struct in6_addr * iaddr, unsigned short iport,
                int proto, const struct memmap_owner * owner, unsigned short * eport,
                char * desc, int desclen, unsigned int * timestamp);

/* The expiry of an IPv4 mapping by its external port, for a firewall backend
 * whose rule does not hold it. 0 : no expiry, or no such row. */
unsigned int memmap_map_expiry(unsigned short eport, int proto);

/* The same for a mapping limited to a remote peer, a PEER or a UPnP mapping with
 * a remote host. Its row has a struct lease_remote. raddr NULL, empty, "*" or ::
 * is any remote host: with rport 0 the same as memmap_map(), else the remote
 * is :: and rport. An IPv6 row is keyed by its remote too. An IPv4 port has one
 * row whatever its remote: a row with another remote is replaced. An IPv4 row
 * is on the port list like any other port mapping. An IPv4 PCP PEER has no row
 * here yet. */
void memmap_remote_peer(unsigned short uid, const char * raddr, unsigned short rport,
                        unsigned short eport, const char * iaddr, unsigned short iport,
                        int proto, const char * desc, unsigned int timestamp);
/* The firewall renewed a UPnP pinhole: give its row the new expiry. PCP has no
 * uid, and renews through memmap_map() with the key of the row. */
void memmap_renew_uid(unsigned short uid, unsigned int timestamp);

/* The firewall removed the pinhole of uid: remove its row, if it has one. */
void memmap_remote_peer_gone(unsigned short uid);

/* The same, for a caller which has the rule too: if no row has the uid, find
 * the row by the rule. This is the case of a PCP pinhole, which has no uid in
 * the table. */
void memmap_remote_peer_gone_at(unsigned short uid, const char * raddr, unsigned short rport,
                                const char * iaddr, unsigned short iport, int proto);
/* For a firewall backend: tell memmap_expire_map6() that this pass leaves
 * expired rules in the firewall, because a delete failed. The rows then stay. */
void memmap_remote_peers_partial(void);

/* The mapping of an external port, with no read of the firewall. family
 * AF_INET with eaddr NULL is an IPv4 port mapping. Fills what is given, and
 * takes NULL for what is not wanted. raddr gets :: for no remote. 0, or -1 if
 * there is none. */
int memmap_get(int family, const struct in6_addr * eaddr, unsigned short eport,
               int proto, unsigned short * iport, struct in6_addr * iaddr,
               char * desc, int desclen, struct memmap_remote * remote,
               unsigned int * timestamp);

/* The IPv4 mapping at this place in the list, oldest first, for the UPnP calls
 * which list mappings by index. 0, or -1 past the end. */
int memmap_get_at(unsigned int index, unsigned short * eport, int * proto,
                  unsigned short * iport, struct in6_addr * iaddr,
                  char * desc, int desclen, struct memmap_remote * remote,
                  unsigned int * timestamp);

/* The kind of the row of an IPv4 port mapping, a LEASE_* value, or -1 if
 * there is none. */
int memmap_map_kind(unsigned short eport, int proto);

/* the number of IPv4 port mappings */
int memmap_map_count(void);

/* The external ports of proto in the range, oldest first, in a malloc'ed array
 * which the caller frees. *number is their count. NULL if there is no memory. */
unsigned short * memmap_ports_in_range(unsigned short startport, unsigned short endport,
                                       int proto, unsigned int * number);

/* 1 if another internal address maps the external port, on any protocol. It
 * logs who. eaddr NULL : ::. */
int memmap_eport_used_by_other(int family, const struct in6_addr * eaddr,
                               unsigned short eport, const struct in6_addr * iaddr);

/* 1 if the external port of key is redirected to another internal endpoint
 * than that of key: by a mapping of ours, from the table, or with iptables by
 * a port forward of another program, from the firewall. For port_in_use(). */
int memmap_eport_redirected_elsewhere(const char * ifname, const struct memmap_key * key);

/* The reads below are those only the firewall can answer. The protocols call
 * them here, and never the firewall backend. */

/* The packet and byte counters of an IPv4 port mapping, which only the kernel
 * has. 0, or -1 if the firewall has no such rule. */
int memmap_map_counters(unsigned short eport, int proto,
                        u_int64_t * packets, u_int64_t * bytes);

/* 1 if the firewall still has the rule of the IPv4 port mapping of key, which
 * has a row. A flush or another program can remove a rule: then drop the row
 * and return 0, so the caller adds the mapping again instead of renewing a
 * closed port. */
int memmap_in_firewall(const struct memmap_key * key);

/* Give a row to each rule of an earlier run which has none, so the rule can be
 * listed and deleted. This reads the firewall, once at startup. */
void memmap_adopt_rules(void);

#ifdef USE_NFTABLES
/* the mappings removed by a pass of the main loop, so that a large expiry
 * does not stop the daemon from answering */
#define EXPIRE_MAX_PER_PASS	64

struct expired_redirect {
	unsigned short eport;
	int proto;
};

/* Fills expired with at most max IPv4 mappings past their lifetime, and next
 * with the next expiry (0 : none, now : more to do), with no read of the
 * firewall. Returns the number filled. */
int memmap_expired_maps(unsigned int now, struct expired_redirect * expired,
                        int max, unsigned int * next);
#endif

#ifdef ENABLE_UPNPPINHOLE
/* The pinhole reads below go to the firewall: a pinhole of an earlier run has
 * no row, and the packet counter is only there. */

/* The uid of the pinhole of this rule, or < 0. desc and timestamp may be NULL. */
int memmap_find_map6(const char * raddr, unsigned short rport,
                        const char * iaddr, unsigned short iport, int proto,
                        char * desc, int desclen, unsigned int * timestamp);
/* The rule of a pinhole. 0, -2 if there is no such pinhole, or < 0. */
int memmap_get_map6(unsigned short uid, char * raddr, int raddrlen,
                       unsigned short * rport, char * iaddr, int iaddrlen,
                       unsigned short * iport, int * proto, char * desc, int desclen,
                       unsigned int * timestamp, u_int64_t * packets);
/* The uid of the pinhole at this place, or < 0 past the end. */
int memmap_map6_uid_at(int index);
/* Remove the pinholes past their expiry, which the firewall holds, and their
 * rows. *next is the time of the next expiry. The number removed, or < 0. */
int memmap_expire_map6(unsigned int * next);
#endif

#ifdef PCP_PEER
/* The PCP PEER rule at this place, from the firewall: a PEER has no row. 0, or
 * -1 past the end. The arguments are those of get_peer_rule_by_index(). */
int memmap_get_peer_at(int index, unsigned short * eport, char * iaddr, int iaddrlen,
                       unsigned short * iport, int * proto, char * desc, int desclen,
                       char * rhost, int rhostlen, unsigned short * rport,
                       unsigned int * timestamp, u_int64_t * packets, u_int64_t * bytes);
/* The external address and port of the connection of int to peer, from the
 * kernel's connection table. 1 if found. */
int memmap_peer_nat_addr(struct sockaddr * intaddr, struct sockaddr * peer,
                         unsigned char proto, struct sockaddr * ext);
#endif

#endif
