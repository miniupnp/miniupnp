/* MiniUPnP project
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

/* The restore at startup: the daemon side of lease_files_load().
 *
 *   init
 *     lease_files_reserve_ids()   the ids of the files stay unused
 *     drop_rules_without_row()    the table is empty: the rules of the
 *                                 earlier run go
 *     lease_restore()
 *       lease_files_load()        a row per line of .mappings, with its
 *                                 filters; a binding per peer of
 *                                 .outgoing.peers, with its .outgoing line
 *       fw_sync_each()            FW_BATCH adds at a time, one by one after
 *                                 a refused batch
 *       fw_sync_out_each()        the same for the PEER bindings
 *       memmap_add()              the rows whose rules are there
 *
 * A row keeps the external address it was saved with: after a change of the
 * WAN address it is found by its old one, as a row made before the change
 * is. */
#ifndef LEASE_RESTORE_H_INCLUDED
#define LEASE_RESTORE_H_INCLUDED

/* Put back the rows and PEER bindings of the lease files. Call it at
 * startup, after lease_files_reserve_ids() and drop_rules_without_row(),
 * so the firewall holds no rule of the daemon and every row is a new add.
 * The rows go to the firewall through fw_sync_each(), FW_BATCH at a time,
 * and into the tables when their rules are there. After a boot with the
 * clock behind the last save, they come later, from lease_files_poll(). The files are trusted:
 * no permission, port or owner check. 0, or -1 if the files could not be
 * read. */
int lease_restore(void);

#endif
