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
 * memmap_sync() is the one write, of the table and of the firewall. iaddr gives
 * the family. An IPv4 row is a port mapping, and an IPv6 row is a pinhole:
 * eport is iport, and the rule is that of a MAP without a remote peer, or of a
 * PEER with one. */
#ifndef MEMMAP_H_INCLUDED
#define MEMMAP_H_INCLUDED

#include <sys/types.h>
#include "config.h"

struct sockaddr;

/* The IPv4 mapping of an internal endpoint, with no read of the firewall. PCP
 * and NAT-PMP ask this to see if a client already has a mapping. Several
 * protocols can map one endpoint: owner (enum mapping_owner) takes the row of
 * that protocol, and -1 the first row of any. Returns 0 if found, else -1. desc
 * and timestamp may be NULL. */
int memmap_find_map(const char * iaddr, unsigned short iport, int proto,
                    int owner, unsigned short * eport, char * desc, int desclen,
                    unsigned int * timestamp);
/* The expiry of an IPv4 mapping by its external port, for a firewall backend
 * whose rule does not hold it. 0 : no expiry, or no such row. */
unsigned int memmap_map_expiry(unsigned short eport, int proto);

/* Renew an IPv4 mapping: a new expiry and description, in the table only. The
 * firewall does not hold the expiry. The caller first asks
 * memmap_map_in_firewall() if the rule is still there. 0, or -1 if the table
 * has no such mapping or no memory for the description. */
int memmap_renew_map(unsigned short eport, int proto, const char * desc,
                     unsigned int expiry);

/* For a firewall backend: tell memmap_expire_pinholes() that this pass leaves
 * expired rules in the firewall, because a delete failed. The rows then stay. */
void memmap_remote_peers_partial(void);

/* The IPv4 mapping of an external port, with no read of the firewall. Fills the
 * strings given, and takes NULL for what is not wanted. 0, or -1 if there is
 * none. */
int memmap_get_map(unsigned short eport, int proto, unsigned short * iport,
                   char * iaddr, int iaddrlen, char * desc, int desclen,
                   char * rhost, int rhostlen, unsigned int * timestamp);

/* The same by its place in the list, oldest first, for the UPnP calls which
 * list mappings by index. 0, or -1 past the end. */
int memmap_get_map_at(unsigned int index, unsigned short * eport, int * proto,
                      unsigned short * iport, char * iaddr, int iaddrlen,
                      char * desc, int desclen, char * rhost, int rhostlen,
                      unsigned int * timestamp);

/* the number of IPv4 port mappings */
int memmap_map_count(void);

/* The external ports of proto in the range, oldest first, in a malloc'ed array
 * which the caller frees. *number is their count. NULL if there is no memory. */
unsigned short * memmap_ports_in_range(unsigned short startport, unsigned short endport,
                                       int proto, unsigned int * number);

/* 1 if another internal address maps the external port, on any protocol. It
 * logs who. */
int memmap_eport_used_by_other(unsigned short eport, const char * iaddr);

/* 1 if the external port is redirected to another internal endpoint than
 * iaddr:iport: by a mapping of ours, from the table, or with iptables by a
 * port forward of another program, from the firewall. For port_in_use(). */
int memmap_eport_redirected_elsewhere(const char * ifname, unsigned short eport, int proto,
                                      const char * iaddr, unsigned short iport);

/* What a change of a request does */
enum memmap_op {
	MEMMAP_ADD,		/* add a port mapping or a pinhole */
	MEMMAP_UPDATE,		/* an IPv4 port mapping: new iport, description, expiry */
	MEMMAP_RENEW,		/* a pinhole by uid: new expiry. With iaddr, its rule */
	MEMMAP_DELETE,		/* an IPv4 port mapping, by eport */
	MEMMAP_DELETE_PINHOLE	/* a pinhole by uid. With iaddr, its rule too */
};

/* One change of a request. The strings stay the caller's. */
struct memmap_change {
	enum memmap_op op;
	const char * raddr;	/* NULL, "" or "*" : any remote */
	unsigned short rport;
	unsigned short eport;	/* a pinhole: unused, it is iport */
	const char * iaddr;	/* gives the family */
	unsigned short iport;
	int proto;
	const char * desc;
	unsigned int timestamp;	/* the expiry, 0 for none */
	int uid;		/* a pinhole: set by MEMMAP_ADD, read by the others */
};

/* Do a request: build its rows in memory, out of the table, and send them to
 * the firewall in one fw_sync(). If the firewall takes the request, the rows
 * go into the table, and the rows they replace or delete go out. If not, the
 * new rows are freed and the table is as before, except for a change the
 * firewall could not take back: its rule stays, and so does its row. Two
 * changes of one request may not go to one row: then nothing is sent. Returns
 * 0, or the negative result of the firewall. */
int memmap_sync(struct memmap_change * changes, int n);

/* The reads below are those only the firewall can answer. The protocols call
 * them here, and never the firewall backend. */

/* The packet and byte counters of an IPv4 port mapping, which only the kernel
 * has. 0, or -1 if the firewall has no such rule. */
int memmap_map_counters(unsigned short eport, int proto,
                        u_int64_t * packets, u_int64_t * bytes);

/* fn(eport, proto, packets, bytes, arg) for each UPnP IPv4 port mapping which
 * has a row and a rule. A PCP or NAT-PMP mapping is left out: it lasts the
 * lifetime its client asked for, so idle counters must not end it. iptables
 * walks its chain once and pf reads its rules by index, once each; the other
 * firewalls are read once per mapping. 0, or -1 if the firewall could not be
 * read. */
typedef void (*memmap_counters_fn)(unsigned short eport, int proto,
                                   u_int64_t packets, u_int64_t bytes, void * arg);
int memmap_each_map_counters(memmap_counters_fn fn, void * arg);

/* 1 if the firewall has the rule of an IPv4 port mapping with a row. A flush
 * or another program can remove a rule: then it is added again from the row,
 * which stays, as the rule of a pinhole is. 0 if there is no row, or the rule
 * could not be added again: then the row goes, so the caller maps anew
 * instead of renewing a closed port. With firewall_trust FW_TRUST_TRUST the
 * firewall is not asked: 1. */
int memmap_map_in_firewall(unsigned short eport, int proto);

/* Give a row to each rule of an earlier run which has none, so the rule can be
 * listed and deleted. This reads the firewall, once at startup. */
void memmap_adopt_rules(void);

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

#ifdef ENABLE_UPNPPINHOLE
/* 1 if the pinhole uid has a row: then it needs no read of the firewall. */
int memmap_pinhole_has_row(unsigned short uid);

/* The pinhole reads below go to the firewall: a pinhole of an earlier run has
 * no row, and the packet counter is only there. */

/* The uid of the pinhole of this rule, or < 0. desc and timestamp may be NULL. */
int memmap_find_pinhole(const char * raddr, unsigned short rport,
                        const char * iaddr, unsigned short iport, int proto,
                        char * desc, int desclen, unsigned int * timestamp);
/* The rule of a pinhole. 0, -2 if there is no such pinhole, or < 0. */
int memmap_get_pinhole(unsigned short uid, char * raddr, int raddrlen,
                       unsigned short * rport, char * iaddr, int iaddrlen,
                       unsigned short * iport, int * proto, char * desc, int desclen,
                       unsigned int * timestamp, u_int64_t * packets);
/* The uid of the pinhole at this place, or < 0 past the end. */
int memmap_pinhole_uid_at(int index);
/* Remove the pinholes past their expiry, which the firewall holds, and their
 * rows. The rules are read only when a pinhole is due. *next is the time of the
 * next expiry. The number removed, or < 0. */
int memmap_expire_pinholes(unsigned int * next);
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
