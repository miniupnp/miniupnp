/* MiniUPnP project
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

/* memmap: keeps the lease table and the outgoing table in step with the
 * firewall. The redirect, pinhole and PEER functions call it once the
 * firewall took a change, and say what the change was: a new rule, or an
 * update of a rule there was. memmap does not look in the table to decide
 * that.
 *
 * A row goes when its rule is deleted, also when an expired one is. The
 * table does not expire rows itself.
 *
 * The protocols read the tables instead of the firewall: the find functions
 * here, and those of lease_table.h and outgoing_table.h for a plain lookup.
 *
 * A row is found by its key, proto + family + iaddr:iport, and its external
 * port: an internal endpoint can have several mappings, one per external
 * port. An IPv6 map without translation (eport = iport) is the one row of its
 * endpoint, and holds a filter per rule, found by its remote. A map with no
 * filter has one rule, of any remote.
 *
 * A row keeps the external address its client was given (eaddr), as there
 * can be several WAN addresses. The protocol fills it; a reloaded row has ::
 * until its next request. memmap only stores it: nothing acts on a WAN
 * address change yet. */
#ifndef MEMMAP_H_INCLUDED
#define MEMMAP_H_INCLUDED

#include "lease_table.h"
#include "outgoing_table.h"

/* The firewall added a rule for e, a row of lease_table_new(). A mapping
 * becomes a row; a rule without translation becomes a filter of the map of
 * its endpoint, or the map itself if there is none. The table takes e: the caller
 * does not use it afterwards. A request on the stack (e->row 0) is not
 * recorded. */
void memmap_add(struct lease_entry * e);

/* The firewall updated the rule of e, a row of lease_table_new(): the rule
 * of its key and eport, which had the internal port iport_old (UPnP may
 * change it). Its row takes the values of e, in place; for a rule without
 * translation, the filter of e's remote and the expiry of the map. The
 * table takes e. */
void memmap_update(struct lease_entry * e, unsigned short iport_old);

/* The rule of r (key, eport) was renewed to r->timestamp: its row takes the
 * expiry, which all the filters of a map share. r is not taken. */
void memmap_renew(const struct lease_entry * r);

/* The mapping of the key and eport was deleted: its row goes. */
void memmap_delete(int proto, int family, const struct in6_addr * iaddr,
                   unsigned short iport, unsigned short eport);

/* The rule without translation of r was deleted: its filter goes, and the
 * map with its last one. The filter is that of the uid of r's first filter
 * (UPnP), else that of its remote in the map of r's key. r with no filter
 * is the rule of any remote: it takes a map with no filter. */
void memmap_delete_filter(const struct lease_entry * r);

/* The firewall took b, a binding of outgoing_table_new(). It goes on the
 * list, or gives its peers to the binding of its key. The table takes b. A
 * request on the stack is not recorded. */
void memmap_link_outgoing(struct outgoing_entry * b);

/* The PEER rule of key to raddr:rport was deleted: the peer goes, and the
 * binding with its last one. key: proto, family, iaddr:iport and
 * eaddr:eport. */
void memmap_drop_outgoing(const struct outgoing_entry * key,
                          const struct in6_addr * raddr, unsigned short rport);

/* The mapping of proto on eaddr:eport, or NULL: the row of eaddr, else the
 * row on eport whose address is :: (a reloaded row, its address not
 * stored). eaddr is the address the protocol tells its client. */
struct lease_entry *
memmap_find_map(int proto, int family, const struct in6_addr * eaddr,
                unsigned short eport);

/* A mapping on eaddr:eport, on any protocol, for another internal address
 * than iaddr, or NULL. eaddr as in memmap_find_map(). */
struct lease_entry *
memmap_eport_used_by_other(int family, const struct in6_addr * eaddr,
                           unsigned short eport, const struct in6_addr * iaddr);

/* Walk the mappings of proto of the internal address iaddr: call with prev
 * NULL for the first row, then with the row it returned, until NULL. Those
 * of iaddr:iport, or with iport 0 the IPv4 port mappings of iaddr on any
 * internal port. A caller may remove the row it got before the next call
 * only if it took the next row first. */
struct lease_entry *
memmap_next_client_map(const struct lease_entry * prev, int proto, int family,
                       const struct in6_addr * iaddr, unsigned short iport);

/* The PEER binding of proto from iaddr:iport which has the peer
 * raddr:rport, on any external address and port, or NULL. raddr NULL: the
 * binding of iaddr:iport with any peer. A PEER is known by its internal
 * side and its peer: the external port is the daemon's. */
struct outgoing_entry *
memmap_find_peer(int proto, int family, const struct in6_addr * iaddr,
                 unsigned short iport, const struct in6_addr * raddr,
                 unsigned short rport);

/* A PEER binding on eaddr:eport, on any protocol, for another internal
 * address than iaddr, or NULL. eaddr as in memmap_find_map(). */
struct outgoing_entry *
memmap_peer_port_used_by_other(int family, const struct in6_addr * eaddr,
                               unsigned short eport, const struct in6_addr * iaddr);

/* For debugging: write the lease table and the outgoing table to path as
 * text. 0, or -1 if the file could not be written. */
int memmap_dump(const char * path);

/* Write the sizes of the tables to path, a "name value" line each, to
 * compare with the rules of the firewall:
 *   map                the rows of the lease table, of any family
 *   map_pcp, map_natpmp, map_upnp   the rows of each protocol
 *   map_ipv4, map_ipv6 the rows by the family of their internal side
 *   map_expired        rows whose expiry is before now, still in the table
 *   map_filters        the filters of all maps
 *   outgoing_bindings  PCP PEER bindings
 *   outgoing_bindings_ipv4, outgoing_bindings_ipv6   the same by family
 *   outgoing           their remotes: an SNAT rule each
 *   next_expiry        seconds from now to next_expiry, < 0 if it is past;
 *                      no line if next_expiry is 0 (nothing to expire)
 * now and next_expiry are on the clock of the expiries (upnp_time()). The
 * file is replaced whole: a reader sees the old one or the new one. 0, or
 * -1 if it could not be written. */
int memmap_stats(const char * path, unsigned int now, unsigned int next_expiry);

#endif
