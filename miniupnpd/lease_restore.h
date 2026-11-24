/* MiniUPnP project
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

/* The restore at startup: the daemon side of lease_files_load(). */
#ifndef LEASE_RESTORE_H_INCLUDED
#define LEASE_RESTORE_H_INCLUDED

/* Put back the rows and PEER bindings of the lease files. Call it at
 * startup, after lease_files_reserve_ids() and drop_rules_without_row(),
 * so the firewall holds no rule of the daemon and every row is a new add.
 * The rows go to the firewall through fw_sync_each(), FW_BATCH at a time,
 * and into the tables when their rules are there. The files are trusted:
 * no permission, port or owner check. 0, or -1 if the files could not be
 * read. */
int lease_restore(void);

#endif
