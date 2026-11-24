/* The outgoing table: the PCP PEER mappings of the daemon, in memory.
 *
 * A PCP PEER is an outgoing SNAT binding (RFC 6887 section 12): an internal
 * endpoint talks out to remote peers, seen from outside on an external
 * address and port. It is not an incoming map or filter, so it is not in the
 * mapping table (lease_table.c), and a PEER and a MAP can use one external
 * port.
 *
 * A binding is the struct outgoing_entry PCP fills (mapreq.h): iaddr:iport
 * out on eaddr:eport, with its nonce. The request and the binding are one
 * struct, so the table copies nothing into a shape of its own: PCP gets an
 * unlinked binding from outgoing_table_new(), fills it in place, and links
 * it once the firewall took it. A binding owns its peer array and its
 * label, and a linked one has one peer at least. Each peer has its own
 * expiry.
 *
 * The bindings are on one list. This file knows nothing of the protocols or
 * the firewall. */
#ifndef OUTGOING_TABLE_H_INCLUDED
#define OUTGOING_TABLE_H_INCLUDED

#include <stdio.h>
#include <netinet/in.h>

#include "mapreq.h"

/* A new binding with room for npeers peers, not on the list: a lookup does
 * not find it until outgoing_table_link(). It is empty, with npeers
 * zeroed peers. NULL if there is no memory. */
struct outgoing_entry * outgoing_table_new(int npeers);

/* Free a binding which is not on the list, with its peers. Its label is
 * still the caller's. */
void outgoing_table_free(struct outgoing_entry * b);

/* Put a binding of outgoing_table_new() on the list, with a copy of its
 * label, which was the caller's until then. If a linked binding has
 * its key, the peers of b go to that one instead: a peer it has gets the
 * expiry of b's, another one is added. The binding of the key takes the
 * nonce of b, and b is freed. The binding which holds the peers, or NULL if
 * there is no memory: the peers of b are then not all in, and b is freed. */
struct outgoing_entry * outgoing_table_link(struct outgoing_entry * b);

/* The binding of the key of r: proto, family, iaddr:iport and eaddr:eport.
 * NULL if there is none. */
struct outgoing_entry * outgoing_table_find(const struct outgoing_entry * r);

/* Walk the bindings: call with prev NULL for the first one, then with the
 * binding it returned, until NULL. */
struct outgoing_entry * outgoing_table_next(const struct outgoing_entry * prev);

/* The peer raddr:rport of a binding, or NULL. */
struct outgoing_peer *
outgoing_table_find_peer(const struct outgoing_entry * b,
                         const struct in6_addr * raddr, unsigned short rport);

/* Remove the peer p of the linked binding b. The binding goes with its last
 * peer: b is then no longer valid. */
void outgoing_table_remove_peer(struct outgoing_entry * b, struct outgoing_peer * p);

/* Remove a linked binding with all its peers. b is no longer valid. */
void outgoing_table_remove(struct outgoing_entry * b);

/* The number of changes of the table so far: a binding or a peer added,
 * renewed or removed. It only grows, as lease_table_changes(). */
unsigned long outgoing_table_changes(void);

/* the number of bindings */
unsigned int outgoing_table_count(void);

/* Give no id up to max, as lease_table_reserve_ids(): the lease files call
 * this at startup with the highest binding id they hold. */
void outgoing_table_reserve_ids(unsigned long long max);

/* The highest binding id given or reserved. */
unsigned long long outgoing_table_last_id(void);

/* the number of peers, all bindings together */
unsigned int outgoing_table_peer_count(void);

/* Remove the peers whose expiry is now or before (timestamp 0 : none), and
 * a binding with its last peer. The number of peers removed. */
unsigned int outgoing_table_expire(unsigned int now);

/* Remove all the bindings. */
void outgoing_table_clear(void);

/* For debugging: write every binding to f, as text: a line per binding,
 * each of its peers an indented line under it. */
void outgoing_table_dump(FILE * f);

#endif
