/* The one write path to the firewall.
 *
 * memmap_sync() builds the rows of a request, and hands them here as a list
 * of changes. fw_sync() turns each row into the rules of the firewall in use,
 * and sends them. The backend keeps no state: what it needs is in the rows.
 *
 * A request succeeds or fails as a whole. A firewall which can apply a batch
 * of rules in one transaction does so. The others add the rules one at a time
 * and, when one fails, take back the changes before it. pf could load a batch
 * in one transaction of its anchor, which replaces every rule of the anchor:
 * with all the mappings in one anchor, that is a cost for every request, so pf
 * waits for the anchors to be split, and adds one rule at a time until then.
 *
 * A change which could not be taken back is marked "applied": its rule is in
 * the firewall, and memmap_sync() keeps the row of it. */
#ifndef FWSYNC_H_INCLUDED
#define FWSYNC_H_INCLUDED

#include "config.h"
#include "lease_table.h"

/* The firewalls which have map6s, and their map6 functions. The PF API
 * of Apple differs from what pf/pfpinhole.c expects. */
#ifdef ENABLE_UPNPPINHOLE
#if defined(USE_NETFILTER) || (defined(USE_PF) && !defined(__APPLE__))
#define FW_MAP6
#include "fwmap6.h"
#endif
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
	FW_HALF_APPLIED		/* a part of the rules of row stayed: the row
				 * must expire at once, so the expiry tries the
				 * delete again */
};

struct fw_change {
	enum fw_op op;
	const struct lease_entry * row;	/* FW_ADD, FW_UPDATE: the new row, not in the table */
	const struct lease_entry * old;	/* FW_UPDATE, FW_DELETE: the rule as it is */
	int old_partial;		/* old holds the key only, as the rule has
					 * no row: the change cannot be taken back */
	enum fw_applied applied;	/* set by fw_sync() */
};

/* Send the changes of one request to the firewall. 0: all are applied. < 0:
 * the request failed, and each change says if it is applied all the same.
 * A map6 rule is found by the key of its row, not by its uid. */
int fw_sync(struct fw_change * changes, int n);

/* The redirect rule of an IPv4 port mapping, and its counters: 0, -2 if the
 * firewall has no such rule, or -1 if the firewall could not be read. The one
 * read of the firewall by eport, for fw_sync() and memmap. */
int fw_map_rule(unsigned short eport, int proto, u_int64_t * packets, u_int64_t * bytes);

#endif
