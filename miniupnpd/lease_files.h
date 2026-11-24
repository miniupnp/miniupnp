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
 *   <lease_file>.checksum	the size and CRC-32 of each of them
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

struct lease_entry;
struct outgoing_entry;

/* A row of the files: e from lease_table_new(), filled, not linked. The
 * callee takes e. Its label points into the line, valid only during the
 * call. */
typedef void (*lease_files_map_fn)(struct lease_entry * e, void * arg);

/* A peer of the files: b from outgoing_table_new(1), filled, not linked.
 * The callee takes b; its label as above. */
typedef void (*lease_files_peer_fn)(struct outgoing_entry * b, void * arg);

/* At startup, before any row is linked: remove the temporary files of a
 * save a crash cut short, and keep the ids the files hold from the rows of
 * this run (the last_id of each header). */
void lease_files_reserve_ids(void);

/* Set by --lease-file-ignore-checksum: a load reads files whose sums do
 * not match .checksum, or which have none, as files edited by hand */
extern int lease_files_ignore_checksum;

/* Read the files at startup: each row of .mappings with its filters to
 * r->map, each line of .outgoing to r->peer, then call r->done. The files are trusted: a line is
 * only skipped (and logged) when it cannot be read, is expired, or is a
 * row of another save (a crash between the renames). 1 if the files were
 * read, 2 if lease_file_restore keeps them from being restored (no, or boot
 * after a boot), 0 if there are none (no .mappings), or -1 if a file is not one this
 * daemon can read, or does not match the size and CRC-32 of .checksum:
 * every file of the set is renamed to <name>.bad, and nothing is read.
 *
 * The expiry of a line is unix time. After a daemon restart in the same
 * boot it is read on the monotonic clock of the save instead, which the
 * header of .mappings has. After a new boot with the clock behind the save
 * (no real-time clock, NTP not done yet) the restore waits: r is kept, and
 * lease_files_poll() reads the rows once the clock has passed the save, or
 * after a few minutes with the lease each row had left at the save. No save
 * runs until then, and a mapping a client made meanwhile keeps its port.
 * Then 1 is returned at once. */
struct lease_files_restore {
	lease_files_map_fn map;
	lease_files_peer_fn peer;
	void (*done)(void * arg);	/* after the last row, NULL : none */
	void * arg;
};

/* The file which holds the id of this boot. Its own variable for the unit
 * test. Where it cannot be read, each start is a new boot. */
extern const char * lease_files_boot_id_path;

int lease_files_load(const struct lease_files_restore * r);

#endif
