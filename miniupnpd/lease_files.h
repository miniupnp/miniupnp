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
 *   <lease_file>.outgoing	one line per outgoing SNAT binding (PCP PEER)
 *   <lease_file>.outgoing.peers	one line per remote peer of an outgoing SNAT
 *				binding (PCP PEER)
 *   <lease_file>.checksum	the size and CRC-32 of each of them
 *
 * Each file starts with its header and the names of its fields, then has
 * one line per row, the fields separated by |:
 *   LEASE-MAPPINGS 1 last_id=3 boot_id=b64c... monotonic=124683 unix=1795546350
 *   id|kind|family|proto|eport|iport|iaddr|eaddr|nonce|since|expiry|ifname|filters|label
 *   1|PCP-M|IPv4|UDP|43333|43333|172.28.12.2|6.18.12.1|a1a2...|1795546343|1795546943|wan0|0|NA
 * The header is the kind of file and its version, then name=value words:
 * last_id, the highest id of the table at the save; monotonic and unix,
 * the two clocks of the save; in .mappings also boot_id. A reader finds a
 * field by its name and skips the fields and words it does not know, so a
 * later version can add fields. NA is "does not apply".
 *
 *   .mappings	id|kind|family|proto|eport|iport|iaddr|eaddr|nonce|since|
 *		expiry|ifname|filters|label
 *	kind UPNP, NAT-PMP or PCP-M; proto TCP, UDP, UDPLITE or its number;
 *	nonce the PCP nonce, 24 hex digits as on the wire; since and expiry
 *	unix time, expiry 0 for none; eaddr the external address the client
 *	was told; ifname the external interface (for tools, not read back);
 *	filters the number of its lines in .filters; label the text of the
 *	client, with \\, \|, \n, \r and \xHH escaped (a label NA is \x4EA).
 *   .filters	map|raddr|rprefix|rport|uid
 *	a remote a row lets in: a UPnP RemoteHost, a pinhole of an IPv6 map
 *	with its UniqueID. map is the id of the row; rprefix is in its family.
 *   .outgoing	id|family|proto|iaddr|iport|eaddr|eport|nonce|ifname|peers|label
 *	peers is the number of its lines in .outgoing.peers.
 *   .outgoing.peers	binding|raddr|rport|since|expiry
 *	binding is the id of its line in .outgoing.
 *   .checksum	file|bytes|crc32
 *	the size and CRC-32 (that of zlib and cksum -a crc32b) of each file,
 *	0|00000000 for none; see lease_files.c for its two lines per file.
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
 * r->map, each peer of .outgoing.peers with its binding of .outgoing to r->peer (a
 * binding of one peer each), then call r->done. The files are trusted: a line is
 * only skipped (and logged) when it cannot be read, is expired, or is a
 * row of another save (a crash between the renames: its count of filters
 * or peers does not match). An expired peer is left out, and its binding
 * comes back with the others. 1 if the files were
 * read, 2 if lease_file_restore keeps them from being restored (no, or boot
 * after a boot), 0 if there are none (no .mappings), or -1 if a file is not one this
 * daemon can read, or does not match the size and CRC-32 of .checksum:
 * every file of the set is renamed to <name>.bad, and nothing is read
 * (--lease-file-ignore-checksum reads it, see lease_files_ignore_checksum).
 *
 * Two clocks: the table keeps each expiry on upnp_time(), the time since
 * boot, which starts over at each boot. The files keep unix time:
 * - a time since boot means nothing after the next boot;
 * - the files are saved only when something changes: a time since boot
 *   becomes a date through the clocks of the last save, and that date
 *   drifts once NTP steps or slews the wall clock after it;
 * - a tool which reads the files sees dates as they are, with no sum on
 *   the clocks of the header;
 * - since and expiry of a row are on one clock: expiry - since is the
 *   length of the lease.
 * A row gets its expiry on upnp_time() back by one of:
 *
 *   restart    expiry on upnp_time()                         wall clock
 *   same boot  monotonic of the save                         not needed
 *              + (line expiry - unix of the save)
 *   new boot   upnp_time() + (line expiry - wall clock now)  needed
 *
 * monotonic and unix of the save are in the header of .mappings.
 *
 * After a new boot a router with no real-time clock has its wall clock in
 * the past (1970, or its firmware date) until NTP sets it. A lease of 600 s
 * saved on 2026-11-24 and read with the clock at 2024-01-01 has about 2.9
 * years left. The rows cannot be added at once and fixed later: the daemon
 * is not told when NTP steps the clock, and a lease which ended while the
 * router was off would get its port opened again.
 *
 * So after a new boot with the clock behind the save the restore waits:
 * - r is kept, and lease_files_poll() reads the rows once the wall clock
 *   has passed the save; it checks the clock at least every
 *   LEASE_FILES_CLOCK_CHECK (5) seconds;
 * - if the clock is still behind after LEASE_FILES_CLOCK_WAIT (300)
 *   seconds, the rows are restored anyway, each with the lease it had left
 *   when the files were last saved: the time the router was off is not
 *   counted;
 * - no save runs until then, and a mapping a client made meanwhile keeps
 *   its port.
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
