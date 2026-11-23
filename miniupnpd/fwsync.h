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

/* The redirect rule of an IPv4 port mapping, and its counters: 0, -2 if the
 * firewall has no such rule, or -1 if the firewall could not be read.
 * packets and bytes may be NULL. */
int fw_map_rule(unsigned short eport, int proto, u_int64_t * packets, u_int64_t * bytes);

#endif
