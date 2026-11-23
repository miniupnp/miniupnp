/* The mapping table: the port mappings and IPv6 maps of the daemon, in memory.
 *
 * UPnP, NAT-PMP and PCP all make the same kind of firewall rule, and they
 * compete for the same external ports. This table has one row for each of
 * those maps, whichever protocol made it. A row holds what the firewall
 * holds badly or not at all: the owner, the lifetime and the description.
 *
 * A row is the struct lease_entry of the map (mapreq.h), as the protocol
 * filled it: the request and the row are one struct, so the table copies
 * nothing into a shape of its own. A protocol gets an unlinked row from
 * lease_table_new(), fills it in place, changes the firewall with it, and
 * links the row on success. A row owns its filter array and its label. A map with no filter lets any remote in. Its filters each let one
 * remote in, and share its expiry. A filter is no part of the key, so two
 * maps may each have a filter for the same remote.
 *
 * A row is one of these:
 * - An IPv4 port mapping: packets to eport go to iaddr:iport.
 * - An IPv6 map: packets to iaddr:iport pass, eaddr:eport is iaddr:iport.
 *   It has a rule per filter, or one rule of any remote if it has no
 *   filter (PCP without FILTER). A UPnP IPv6 map has one filter at least,
 *   and names each of them by a uid.
 *
 * Three indexes find a row:
 * - The external index, by protocol, family, eaddr and eport.
 * - The internal index, by protocol, family, iaddr and iport. Several rows can
 *   share an internal endpoint.
 * - The UID index, by the uid of a filter. It gives the filter, and
 *   map_filter.map its row.
 *
 * The IPv4 port mappings are also on a list, oldest first, because UPnP lists
 * them by a position which must stay the same between its calls. A hash has
 * no such order.
 *
 * The table knows nothing of the protocols or the firewall. Callers keep the
 * external keys and uids unique. The daemon has one thread, so there are no
 * locks. */
#ifndef LEASE_TABLE_H_INCLUDED
#define LEASE_TABLE_H_INCLUDED

#include <stdio.h>
#include <time.h>
#include <netinet/in.h>

#include "mapreq.h"

/* A new row with room for nfilters filters, in no index: a lookup does not
 * find it until lease_table_link(). It is empty, with nfilters zeroed
 * filters, each with its map set. NULL if there is no memory. A protocol
 * fills it in place and links it once the firewall took it, so a failed
 * request only frees a row nobody saw. */
struct lease_entry * lease_table_new(int nfilters);

/* Free a row which is in no index, with its filters. Its label is still
 * the caller's. */
void lease_table_free(struct lease_entry * e);

/* Put a row of lease_table_new() in all the indexes, and on the port list if
 * it is an IPv4 port mapping. The row takes a copy of its label, which was
 * the caller's until then. The caller makes sure no linked row has the same
 * external key. */
void lease_table_link(struct lease_entry * e);

/* Link e in the place of old, which goes: e gets the id of old if it has
 * none, and an IPv4 mapping keeps its place on the port list, so the UPnP
 * index of the mappings after it does not move. */
void lease_table_link_in_place(struct lease_entry * e, struct lease_entry * old);

/* Take the row out of the indexes and free it, with its label. e is no
 * longer valid. */
void lease_table_remove(struct lease_entry * e);

/* Give no id up to max: the next ids go on after it. The lease files call
 * this at startup with the highest id they hold, before any row is linked. */
void lease_table_reserve_ids(unsigned long long max);

/* The highest id given or reserved: no row has a higher one. */
unsigned long long lease_table_last_id(void);

/* Replace the label of a linked row: a copy of label, NULL : none. 0, or -1
 * if there is no memory, and then the old label stays. */
int lease_table_set_label(struct lease_entry * e, const char * label);

/* Set the expiry of a row, on the clock of upnp_time(). */
void lease_table_set_expiry(struct lease_entry * e, unsigned int timestamp);

/* The row of an external key, or NULL. */
struct lease_entry *
lease_table_find_mapping(int proto, int family, const struct in6_addr * eaddr,
                         unsigned short eport);

/* A row on this external port for another internal address, on any protocol,
 * or NULL. An IPv4 external port goes to one host. */
struct lease_entry *
lease_table_port_used_by_other(int family, const struct in6_addr * eaddr,
                               unsigned short eport, const struct in6_addr * iaddr);

/* Walk the rows of an internal endpoint: call with prev NULL for the first
 * row, then with the row it returned, until NULL. */
struct lease_entry *
lease_table_next_internal(const struct lease_entry * prev, int proto, int family,
                          const struct in6_addr * iaddr, unsigned short iport);

/* The row of the internal endpoint iaddr:iport on the external port eport,
 * or NULL. An endpoint can have several rows, one per external port; an IPv6
 * map without translation has one, on eport = iport. */
struct lease_entry *
lease_table_find_entry(int proto, int family, const struct in6_addr * iaddr,
                       unsigned short iport, unsigned short eport);

/* The filter with this uid, of a linked row, or NULL. uid 0 finds nothing. */
struct map_filter * lease_table_find_uid(unsigned short uid);

/* A uid for a new UPnP IPv6 filter, 1 to 65534 as the backends give them:
 * the next one after the last given which no filter holds, also after the
 * wrap. 0 if every uid is in use. */
unsigned short lease_table_new_uid(void);

/* Give f, a filter of a row, the uid uid, nonzero: it is in the UID index
 * while its row is linked. */
void lease_filter_set_uid(struct map_filter * f, unsigned short uid);

/* Add a filter to a row, linked or not: a copy of *f. The filter array may
 * move, so the filters of the row are found again by their index, and the
 * UID index follows them. The new filter, or NULL if there is no memory. */
struct map_filter *
lease_filter_add(struct lease_entry * e, const struct map_filter * f);

/* Take f off the filters of its row, linked or not. The filters after it move
 * down one place. */
void lease_filter_drop(struct lease_entry * e, struct map_filter * f);

/* The filter of a row with this remote, or NULL. */
struct map_filter *
lease_filter_find(const struct lease_entry * e, const struct in6_addr * raddr,
                  unsigned char prefix, unsigned short rport);

/* The IPv4 port mapping at this place in the list, or NULL past the end.
 * A client reads the list at index 0, 1, 2..., so this remembers where it
 * stopped and goes on from there. A remove forgets the place. */
struct lease_entry * lease_table_port_at(unsigned int index);

/* the number of IPv4 port mappings */
unsigned int lease_table_port_count(void);

/* Walk the list, oldest first: call with prev NULL for the first row, then
 * with the row it returned, until NULL. */
struct lease_entry * lease_table_next_port(const struct lease_entry * prev);

/* Call cb for every row, in no set order. cb may remove the row it gets, and
 * no other. It may not add a row. */
void lease_table_foreach(void (*cb)(struct lease_entry *, void *), void * arg);

/* The tables of the map, as the lease files keep them: the rows, the
 * remotes of their filters, and the FILTER peers of a PCP MAP (none yet). */
enum lease_table_part { LEASE_T_MAPPINGS, LEASE_T_REMOTES, LEASE_T_FILTERS,
                        LEASE_T_PARTS };

/* The number of changes of a table so far. It only grows, so a reader which
 * kept the number of its last look knows if the table changed since. */
unsigned long lease_table_changes(enum lease_table_part part);

/* Count a change made in place to a linked row: a field the functions here
 * do not set. */
void lease_table_touch(const struct lease_entry * e);

/* 1 if two rows have one owner: the same kind, family, proto, iaddr, iport
 * and nonce. UPnP and NAT-PMP have a zero nonce: the rest names the owner.
 * The eport is no part of it. */
int lease_table_same_owner(const struct lease_entry * a,
                           const struct lease_entry * b);

/* the number of rows */
unsigned int lease_table_count(void);

/* the number of filters of the linked rows, all maps together */
unsigned int lease_table_filter_count(void);

/* Remove all the rows and free the indexes. */
void lease_table_clear(void);

/* For debugging: write every row to f, as text, the IPv4 port mappings in
 * the order of the list, then the IPv6 maps. A row is a line, each of its
 * filters an indented line under it. */
void lease_table_dump(FILE * f);

#endif
