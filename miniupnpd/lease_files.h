/* MiniUPnP project
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

/* The lease files: the tables of the daemon, kept on disk.
 *
 * One file per part of the tables, beside the lease_file of the
 * configuration:
 *   <lease_file>.mappings	one line per row of the lease table
 *   <lease_file>.filters	one line per filter of a row: a remote it lets in
 *   <lease_file>.outgoing	one line per peer of a PCP PEER binding
 *
 * They are written from the tables only, never from the firewall, and no
 * request writes them. The main loop calls lease_files_poll(), which writes
 * the changed parts when the daemon is idle, at most every
 * LEASE_FILES_MIN_GAP seconds, and at the latest LEASE_FILES_MAX_DELAY
 * seconds after the first change. */
#ifndef LEASE_FILES_H_INCLUDED
#define LEASE_FILES_H_INCLUDED

#include <sys/time.h>

#define LEASE_FILES_MIN_GAP	2
#define LEASE_FILES_MAX_DELAY	10

/* Call once per pass of the main loop, before select(). idle is 1 if the
 * last select() had nothing to answer. Writes the changed parts when they
 * are due, else lowers *timeout so the loop wakes up when they are. */
void lease_files_poll(int idle, struct timeval * timeout);

/* Write the changed parts now, whatever the time: at shutdown and on
 * SIGUSR2. Before the first lease_files_poll() it writes nothing: a daemon
 * which stops during its startup leaves the files as they were.
 * 0, or -1 if a file could not be written. */
int lease_files_flush(void);

#endif
