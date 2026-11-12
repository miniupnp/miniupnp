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
#include <netinet/in.h>
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
	MEMMAP_DELETE_PINHOLE	/* a pinhole by uid, or by its rule (iaddr) */
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
	int uid;		/* a pinhole: set by MEMMAP_ADD, read by the others. 0 : none */
	int give_uid;		/* MEMMAP_ADD of a pinhole: 1 gives it a uid, which UPnP
				 * names it by. PCP finds a pinhole by its rule: 0 */
};

/* Fill a change, with every field it does not name zero. A pinhole has no
 * eport of its own: pass its iport. */
void memmap_change_init(struct memmap_change * c, enum memmap_op op, int uid,
                        const char * raddr, unsigned short rport, unsigned short eport,
                        const char * iaddr, unsigned short iport, int proto,
                        const char * desc, unsigned int timestamp);

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
 * has. 0, -2 if the firewall has no such rule, or -1 if it could not be
 * read. */
int memmap_map_counters(unsigned short eport, int proto,
                        u_int64_t * packets, u_int64_t * bytes);

/* fn(eport, proto, packets, bytes, arg) for each UPnP IPv4 port mapping which
 * has a row and a rule. A PCP or NAT-PMP mapping is left out: it lasts the
 * lifetime its client asked for, so idle counters must not end it. iptables
 * walks its chain once. pf reads its rules by index, as master's cleanup
 * pass does: each read walks the rules to its index (OpenBSD 7.4 and later
 * with one ioctl per rule), so a pass costs n^2/2 rule steps. The other
 * firewalls are read once per mapping. 0, or -1 if the firewall could not be
 * read. */
typedef void (*memmap_counters_fn)(unsigned short eport, int proto,
                                   u_int64_t packets, u_int64_t bytes, void * arg);
int memmap_each_map_counters(memmap_counters_fn fn, void * arg);

/* 1 if the firewall has the rule of an IPv4 port mapping with a row. A flush
 * or another program can remove a rule: then it is added again from the row,
 * which stays, as the rule of a pinhole is. 0 if there is no row, or the rule
 * could not be added again: then the row goes, so the caller maps anew
 * instead of renewing a closed port. A firewall which cannot be read gives 1:
 * the rule is not added a second time. With firewall_trust FW_TRUST_TRUST the
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
/* The pinholes, read from the table. Each one has a row: the rules of an
 * earlier run which have none are deleted at startup, by
 * memmap_remove_old_pinholes(). A UPnP pinhole also has a uid, its UniqueID.
 * A PCP pinhole has none (uid 0): PCP finds it by its rule. */

/* The uid of the pinhole of this rule, 0 if it has none, or -2 if there is
 * no such pinhole. desc and timestamp may be NULL. */
int memmap_find_pinhole(const char * raddr, unsigned short rport,
                        const char * iaddr, unsigned short iport, int proto,
                        char * desc, int desclen, unsigned int * timestamp);
/* The rule of a pinhole, with its packet counter from the firewall. raddr is
 * "" for none. 0, or -2 if there is no such pinhole. */
int memmap_get_pinhole(unsigned short uid, char * raddr, int raddrlen,
                       unsigned short * rport, char * iaddr, int iaddrlen,
                       unsigned short * iport, int * proto, char * desc, int desclen,
                       unsigned int * timestamp, u_int64_t * packets);
/* The uid of the pinhole at this place in a walk of the pinholes which have a
 * uid, or -1 past the end. The order is that of the table, and changes with
 * it. */
int memmap_pinhole_uid_at(int index);
/* Renew a pinhole: a new expiry, and a new description unless desc is NULL, in
 * the table. The expiry is the table's, so the firewall changes only if it lost
 * the rule, which is then added again; with firewall_trust FW_TRUST_TRUST it
 * is not asked. 0, -1 if there is no such pinhole, -2 if
 * there is no memory, -3 if the lost rule could not be added again. */
int memmap_renew_pinhole(unsigned short uid, const char * desc, unsigned int expiry);
/* The same, for the pinhole of this rule, which may have no uid (PCP). With
 * give_uid, a pinhole with no uid gets one (UPnP). Its uid (0 : none), or < 0
 * as for memmap_renew_pinhole(), and -4 if there is no free uid. */
int memmap_renew_pinhole_at(const char * raddr, unsigned short rport,
                            const char * iaddr, unsigned short iport, int proto,
                            const char * desc, unsigned int expiry, int give_uid);
/* the pinholes removed by a pass of the main loop */
#define PINHOLE_EXPIRE_PER_PASS	64

/* a pinhole past its expiry, with its rule */
struct expired_pinhole {
	unsigned short uid;
	int proto;
	unsigned short iport;
	unsigned short rport;
	char iaddr[INET6_ADDRSTRLEN];
	char raddr[INET6_ADDRSTRLEN];	/* "" : any remote */
};

/* Fills expired with at most max pinholes past their lifetime, and next with
 * the next expiry (0 : none, now : more to do), from the table with no read of
 * the firewall. Returns the number filled. */
int memmap_expired_pinholes(unsigned int now, struct expired_pinhole * expired,
                            int max, unsigned int * next);

/* Delete the pinhole rules of an earlier run which have no row: their expiry
 * is not known. This reads the firewall, once at startup. */
void memmap_remove_old_pinholes(void);
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
