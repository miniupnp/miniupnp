/* MiniUPnP project
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

/* fw_sync(): the one write path to the firewall.
 *
 * A request hands its rule changes here as a list. fw_sync() turns each row
 * into the rules of the firewall in use, and sends them. It neither reads
 * nor writes the lease table: the caller records in memmap what was
 * applied (memmap.h), and frees the rows of a refused request.
 *
 * A request succeeds or fails as a whole. The rules go one at a time, and
 * when one fails the changes before it are taken back. A change which could
 * not be taken back says so in its applied field: its rule is in the
 * firewall, and the caller keeps the row of it. */
#ifndef FWSYNC_H_INCLUDED
#define FWSYNC_H_INCLUDED

#include "config.h"
#include "mapreq.h"

/* the firewalls which have map6 rules (IPv6 maps, UPnP pinholes), found by
 * their key */
#if defined(ENABLE_UPNPPINHOLE) && \
    (defined(USE_NETFILTER) || (defined(USE_PF) && !defined(__APPLE__)))
#define FW_MAP6
#endif

enum fw_op {
	FW_ADD,		/* add the rules of row */
	FW_UPDATE,	/* change the rules of old into those of row */
	FW_DELETE	/* delete the rules of old */
};

/* what fw_sync() did with a change */
enum fw_applied {
	FW_NOT_APPLIED = 0,	/* the firewall is as before the change */
	FW_APPLIED,		/* the firewall has the change */
	FW_HALF_APPLIED		/* a part of the rules of row stayed, or of old
				 * came back when a delete was taken back */
};

struct fw_change {
	enum fw_op op;
	const struct lease_entry * row;	/* FW_ADD, FW_UPDATE: the new values */
	const struct lease_entry * old;	/* FW_UPDATE, FW_DELETE: the rule as it is,
					 * a row of the table */
	int fresh;			/* FW_ADD: the port has no rule before the
					 * add, so a rule found after a failed add
					 * is its own */
	enum fw_applied applied;	/* set by fw_sync() */
};

/* Fill a change. row and old as in struct fw_change, NULL if the op takes
 * none. */
void fw_change_init(struct fw_change * c, enum fw_op op,
                    const struct lease_entry * row, const struct lease_entry * old);


/* Send the changes of one request to the firewall. 0: all are applied.
 * < 0: the request failed, and each change says if it is applied all the
 * same. */
int fw_sync(struct fw_change * changes, int n);

/* The outgoing side, apart from the incoming maps as the outgoing table is
 * apart from the lease table: the PEER rules (SNAT) of the bindings. They
 * exist with PCP_PEER on netfilter only; elsewhere a change fails. */
enum fw_out_op {
	FW_OUT_ADD,	/* add the rules of binding b to its peer number peer */
	FW_OUT_DELETE	/* delete the rules of binding b to its peer number peer */
};

struct fw_out_change {
	enum fw_out_op op;
	const struct outgoing_entry * b;	/* the binding, with its external port */
	int peer;			/* the index of the peer in b */
	unsigned char dscp_up;		/* FW_OUT_ADD: PCP FLOWDATA, 0 : none */
	unsigned char dscp_down;
	enum fw_applied applied;	/* set by fw_sync_out() */
};

void fw_out_change_init(struct fw_out_change * c, enum fw_out_op op,
                        const struct outgoing_entry * b, int peer);

/* Send the outgoing changes of one request, as fw_sync() does the
 * incoming ones: in order, and those before a failure taken back. */
int fw_sync_out(struct fw_out_change * changes, int n);

/* The redirect rule of an IPv4 port mapping, and its counters: 0, -2 if the
 * firewall has no such rule, or -1 if the firewall could not be read.
 * packets and bytes may be NULL. */
int fw_map_rule(unsigned short eport, int proto, u_int64_t * packets, u_int64_t * bytes);

/* The redirect rule of the IPv4 port e->eport, e->proto, as a row: its
 * internal address and port and its remote host into e, a row of
 * lease_table_new(1). 0, -2 if the firewall has no such rule, or -1 if it
 * could not be read. For the rules of an earlier run, at startup. */
int fw_read_map(struct lease_entry * e);

/* Walk the rules of the daemon's chains or anchors, to find those of an
 * earlier run at startup. Each takes the place i, from 0, and gives the
 * rule there as a row: 0, 1 for a rule which is no row (no address of its
 * family), or -1 past the end or when the rules cannot be read. A delete
 * moves the rules after it down by one. */

/* The IPv4 redirect rule at i, into e, a row of lease_table_new(1). */
int fw_map_rule_at(int i, struct lease_entry * e);

#ifdef FW_MAP6
/* The map6 rule at i, as an IPv6 map of one filter, into e, a row of
 * lease_table_new(1). A rule of any remote is a map with no filter. */
int fw_map6_rule_at(int i, struct lease_entry * e);
#endif

#if defined(PCP_PEER) && defined(USE_NETFILTER)
/* The PEER rule at i, as a binding of one peer, into b, which has room
 * for one. */
int fw_peer_rule_at(int i, struct outgoing_entry * b);
#endif

/* The renewal check of a row of the table: is its firewall side as the row
 * says? An IPv4 mapping is read by its external port, an IPv6 map by the
 * key of each filter.
 *   0   the firewall has it
 *   1   it was gone, or another program pointed the port at another
 *       internal client, and the rules of the row were sent again
 *  -1   the firewall could not be read: nothing is known, nothing changed
 *  -2   it was gone and could not be sent again
 * A part of the rules which stays after a failed send marks the row
 * fw_partial. */
int fw_check_row(struct lease_entry * e);

#ifdef FW_MAP6
/* The packet counter of the rule of filter i of the IPv6 map e: 0, -2 if
 * there is no such rule, or < 0. */
int fw_map6_packets(const struct lease_entry * e, int i, u_int64_t * packets);
#endif

/* fn(eport, proto, packets, bytes, arg) for each IPv4 redirect rule of the
 * firewall, in one pass over the rules where the firewall can: the packet
 * and byte counters, which only the kernel has. 0, or -1 if the rules
 * could not be read. */
typedef void (*fw_counters_fn)(unsigned short eport, int proto,
                               u_int64_t packets, u_int64_t bytes, void * arg);
int fw_each_map_counters(fw_counters_fn fn, void * arg);

#endif
