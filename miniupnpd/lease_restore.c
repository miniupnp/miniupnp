/* MiniUPnP project
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

/* The restore at startup. See lease_restore.h. */
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "config.h"
#include "upnputils.h"
#include "upnpredirect.h"
#include "memmap.h"
#include "fwsync.h"
#include "lease_files.h"
#include "lease_restore.h"

/* The rows and bindings read but not yet sent: one batch of each. A label
 * is a copy of the one of the line, which lives only during the callback. */
struct restore {
	struct lease_entry * rows[FW_BATCH];
	struct fw_change c[FW_BATCH];
	int nrows;
	struct outgoing_entry * peers[FW_BATCH];
	struct fw_out_change oc[FW_BATCH];
	int npeers;
	unsigned int done, failed;
};

/* A copy of the label, which the table copies again when it links */
static const char *
own_label(const char * label)
{
	return label != NULL ? strdup(label) : NULL;
}

static void
send_rows(struct restore * rs)
{
	struct lease_entry * e;
	const char * label;
	int i;

	if(rs->nrows == 0)
		return;
	for(i = 0; i < rs->nrows; i++) {
		fw_change_init(&rs->c[i], FW_ADD, rs->rows[i], NULL);
		rs->c[i].fresh = 1;	/* the firewall has no rule of the daemon */
	}
	(void)fw_sync_each(rs->c, rs->nrows);
	for(i = 0; i < rs->nrows; i++) {
		e = rs->rows[i];
		label = e->label;
		switch(rs->c[i].applied) {
		case FW_APPLIED:
			if(e->timestamp > 0)
				next_to_clean(e->timestamp);
			memmap_add(e);	/* the table takes e, and copies the label */
			rs->done++;
			break;
		case FW_HALF_APPLIED:
			keep_partial_row(e);
			lease_table_free(e);
			rs->failed++;
			break;
		default:
			syslog(LOG_WARNING, "lease files: port %hu %s could not be restored",
			       e->eport, proto_itoa(e->proto));
			lease_table_free(e);
			rs->failed++;
		}
		free((char *)label);
	}
	rs->nrows = 0;
}

static void
send_peers(struct restore * rs)
{
	struct outgoing_entry * b;
	const char * label;
	int i;

	if(rs->npeers == 0)
		return;
	for(i = 0; i < rs->npeers; i++)
		fw_out_change_init(&rs->oc[i], FW_OUT_ADD, rs->peers[i], 0);
	(void)fw_sync_out_each(rs->oc, rs->npeers);
	for(i = 0; i < rs->npeers; i++) {
		b = rs->peers[i];
		label = b->label;
		if(rs->oc[i].applied == FW_APPLIED) {
			if(b->peers[0].timestamp > 0)
				next_to_clean(b->peers[0].timestamp);
			memmap_link_outgoing(b);	/* the table takes b */
			rs->done++;
		} else {
			syslog(LOG_WARNING, "lease files: PEER %hu %s could not be restored%s",
			       b->eport, proto_itoa(b->proto),
			       rs->oc[i].applied == FW_HALF_APPLIED ? ", a part of its rules stays" : "");
			outgoing_table_free(b);
			rs->failed++;
		}
		free((char *)label);
	}
	rs->npeers = 0;
}

static void
restore_map(struct lease_entry * e, void * arg)
{
	struct restore * rs = arg;
	e->label = own_label(e->label);
	rs->rows[rs->nrows++] = e;
	if(rs->nrows == FW_BATCH)
		send_rows(rs);
}

static void
restore_peer(struct outgoing_entry * b, void * arg)
{
	struct restore * rs = arg;
	b->label = own_label(b->label);
	rs->peers[rs->npeers++] = b;
	if(rs->npeers == FW_BATCH)
		send_peers(rs);
}

int
lease_restore(void)
{
	static struct restore rs;
	int r;

	memset(&rs, 0, sizeof(rs));
	r = lease_files_load(restore_map, restore_peer, &rs);
	send_rows(&rs);
	send_peers(&rs);
	if(r > 0)
		syslog(LOG_INFO, "lease files: restored %u mappings and PEER peers, %u not",
		       rs.done, rs.failed);
	return r < 0 ? -1 : 0;
}
