/* MiniUPnP project
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

/* The lease files: the tables of the daemon, kept on disk. See lease_files.h.
 *
 * Each file starts with its header and the names of its fields:
 *   LEASE-MAPPINGS 1 last_id=42
 *   id|kind|family|proto|eport|iport|iaddr|eaddr|nonce|expiry|filters|label
 * then one line per row. A reader finds a field by its name, so a later
 * version can add fields. A field which does not apply is NA. The header
 * goes on with name=value words; a reader skips those it does not know.
 * last_id is the highest id the table had given at the save.
 *
 * A line of .filters names its row by the id of the row, and the filters
 * field of .mappings counts its lines. A line of .outgoing is one peer of a
 * PEER binding; the lines of one binding share its key.
 *
 * A save writes each changed part to a temporary file, then renames them:
 * .checksum first, then .filters and .outgoing, then .mappings. .checksum
 * has the size and CRC-32 of each of them, both as it is on the disk and
 * as the save writes it, so each file matches it whatever the rename a
 * crash cut the save at (0|00000000 : no file):
 *   LEASE-CHECKSUM 1 last_id=42
 *   file|bytes|crc32
 *   mappings|1234|89abcdef
 *   mappings|1250|01234567
 * A load reads no file which does not match it. */
#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <syslog.h>
#include <dirent.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "upnpglobalvars.h"
#include "upnputils.h"
#include "lease_table.h"
#include "outgoing_table.h"
#include "lease_files.h"

#ifdef ENABLE_LEASEFILE

#define LEASE_SEP	'|'
#define LEASE_NA	"NA"
/* A temporary file of a save: <name><suffix>.tmp.XXXXXX */
#define LEASE_TMP	".tmp."

/* the kinds of a row as the files name them */
static const struct {
	int kind;
	const char * name;
} kind_names[] = {
	{ MAP_KIND_UPNP, "UPNP" },
	{ MAP_KIND_NATPMP, "NAT-PMP" },
	{ MAP_KIND_PCP, "PCP-M" },
};
#define KIND_NAMES	(sizeof(kind_names) / sizeof(kind_names[0]))

static const char *
kind_name(int kind)
{
	unsigned int i;
	for(i = 0; i < KIND_NAMES; i++)
		if(kind_names[i].kind == kind)
			return kind_names[i].name;
	return LEASE_NA;	/* no row of the table has another kind */
}

/* Both clocks at the save, read once: the expiry of every line uses them,
 * and the header of .mappings has them */
static long long save_unix, save_mono;

/* An expiry on the clock of upnp_time(), as unix time in an unsigned 32-bit
 * number, the epoch time of PCP. 0 : no expiry. */
static unsigned int
unix_expiry(unsigned int expiry)
{
	long long t;
	if(expiry == 0)
		return 0;
	t = (long long)expiry - save_mono + save_unix;
	if(t < 1)
		t = 1;	/* expired: a load skips it */
	if(t > 0xffffffffLL)
		t = 0xffffffffLL;
	return (unsigned int)t;
}

/* An address in the family of its row. NA for ::. */
static void
put_addr(FILE * f, int family, const struct in6_addr * a)
{
	char buf[INET6_ADDRSTRLEN];
	const char * s = NULL;
	if(!IN6_IS_ADDR_UNSPECIFIED(a))
		s = map_ntop(family, a, buf, sizeof(buf));
	fputs(s != NULL ? s : LEASE_NA, f);
}

/* The protocol by its name where the name reads back as it (TCP, UDP,
 * UDPLITE), else by its number: PCP maps any protocol, 0 for all. */
static void
put_proto(FILE * f, int proto)
{
	const char * name = proto_itoa(proto);
	if(proto_atoi(name) == proto)
		fputs(name, f);
	else
		fprintf(f, "%d", proto);
}

/* The label as the file has it: \\ for a backslash, \| for the separator,
 * \n, \r and \xHH for the other control characters. NA if there is none,
 * and \x4EA for a label which is really NA, so it is not taken for none. */
static void
put_label(FILE * f, const char * label)
{
	const unsigned char * p;
	if(label == NULL || label[0] == '\0') {
		fputs(LEASE_NA, f);
		return;
	}
	if(strcmp(label, LEASE_NA) == 0) {
		fputs("\\x4EA", f);
		return;
	}
	for(p = (const unsigned char *)label; *p; p++) {
		if(*p == '\\' || *p == LEASE_SEP) {
			fputc('\\', f);
			fputc(*p, f);
		} else if(*p == '\n')
			fputs("\\n", f);
		else if(*p == '\r')
			fputs("\\r", f);
		else if(*p < ' ' || *p == 0x7f)
			fprintf(f, "\\x%02x", *p);
		else
			fputc(*p, f);
	}
}

/* One line of .mappings: a lease_table_foreach() callback, arg the file */
static void
put_mapping(struct lease_entry * e, void * arg)
{
	FILE * f = arg;
	char nonce[2 * MAP_NONCE_LEN + 1];

	fprintf(f, "%llu|%s|%s|", e->id, kind_name(e->kind),
	        map_family_name(e->family));
	put_proto(f, e->proto);
	fprintf(f, "|%hu|%hu|", e->eport, e->iport);
	put_addr(f, e->family, &e->iaddr);
	fputc(LEASE_SEP, f);
	put_addr(f, e->family, &e->eaddr);
	fprintf(f, "|%s|%u|%d|", e->kind == MAP_KIND_PCP ? map_nonce_ntop(e->nonce, nonce) : LEASE_NA,
	        unix_expiry(e->timestamp), e->nfilters);
	put_label(f, e->label);
	fputc('\n', f);
}

/* The lines of .filters of a row, one per filter: as put_mapping(). The
 * prefix is that of the family of the row. */
static void
put_filters(struct lease_entry * e, void * arg)
{
	FILE * f = arg;
	const struct map_filter * r;
	int i;
	for(i = 0; i < e->nfilters; i++) {
		r = &e->filters[i];
		fprintf(f, "%llu|", e->id);
		put_addr(f, e->family, &r->raddr);
		fprintf(f, "|%d|%hu|", map_prefix_ntop(e->family, r->prefix), r->rport);
		if(r->uid != 0)
			fprintf(f, "%hu\n", r->uid);
		else
			fputs(LEASE_NA "\n", f);
	}
}

static void
write_mappings(FILE * f)
{
	lease_table_foreach(put_mapping, f);
}

static void
write_filters(FILE * f)
{
	lease_table_foreach(put_filters, f);
}

/* One line per peer of each binding */
static void
write_outgoing(FILE * f)
{
	const struct outgoing_entry * b;
	const struct outgoing_peer * p;
	char nonce[2 * MAP_NONCE_LEN + 1];
	int i;
	for(b = outgoing_table_next(NULL); b != NULL; b = outgoing_table_next(b)) {
		map_nonce_ntop(b->nonce, nonce);
		for(i = 0; i < b->npeers; i++) {
			p = &b->peers[i];
			fprintf(f, "%s|", map_family_name(b->family));
			put_proto(f, b->proto);
			fputc(LEASE_SEP, f);
			put_addr(f, b->family, &b->iaddr);
			fprintf(f, "|%hu|", b->iport);
			put_addr(f, b->family, &b->eaddr);
			fprintf(f, "|%hu|%s|", b->eport, nonce);
			put_addr(f, b->family, &p->raddr);
			fprintf(f, "|%hu|%u|", p->rport, unix_expiry(p->timestamp));
			put_label(f, b->label);
			fputc('\n', f);
		}
	}
}

static unsigned long
mappings_changes(void)
{
	return lease_table_changes(LEASE_T_MAPPINGS);
}

static unsigned long
filters_changes(void)
{
	return lease_table_changes(LEASE_T_FILTERS);
}

/* The size and CRC-32 of a file of the set, as .checksum has them. A file
 * which is not there has 0 and 0: a file of the set is never empty. */
struct file_sum {
	unsigned long long bytes;
	unsigned long crc;
};

static void write_checksum(FILE * f);

/* The data files in the order of their rename: .mappings after its side
 * files, so they are never older than it. .checksum is renamed before them.
 * Each data file with the change count of the table part it holds, and its
 * writer. */
enum lease_file_id { LF_FILTERS, LF_OUTGOING, LF_MAPPINGS, LF_CHECKSUM, LF_COUNT };
#define LF_DATA	LF_CHECKSUM	/* the files before it hold the tables */

static const struct lease_part {
	const char * suffix;
	const char * header;
	const char * names;
	unsigned long (*changes)(void);
	void (*write)(FILE * f);
} lease_parts[LF_COUNT] = {
	{ ".filters", "LEASE-FILTERS 1", "map|raddr|rprefix|rport|uid",
	  filters_changes, write_filters },
	{ ".outgoing", "LEASE-OUTGOING 1",
	  "family|proto|iaddr|iport|eaddr|eport|nonce|raddr|rport|expiry|label",
	  outgoing_table_changes, write_outgoing },
	{ ".mappings", "LEASE-MAPPINGS 1",
	  "id|kind|family|proto|eport|iport|iaddr|eaddr|nonce|expiry|filters|label",
	  mappings_changes, write_mappings },
	{ ".checksum", "LEASE-CHECKSUM 1", "file|bytes|crc32",
	  NULL, write_checksum },
};

int lease_files_ignore_checksum = 0;

/* The sums of the data files as they are on disk (read once, at the first
 * save), and those a save is about to rename; write_checksum() writes
 * both */
static struct file_sum sums[LF_DATA];
static int sums_known;
static const struct file_sum * sums_to_write;

/* The change counts of each part at the last save. They start unlike any
 * count, so the first save writes every file. */
static unsigned long saved[LF_DATA] = {
	(unsigned long)-1, (unsigned long)-1, (unsigned long)-1
};
static time_t last_save;	/* upnp_time() at the end of the last save */
static time_t first_change;	/* of the first change since, 0 : none */
/* After a failed save: when to try again, 0 : no failure. The wait doubles
 * up to LEASE_FILES_MAX_BACKOFF, and only the first failure logs an error, so
 * a full or read-only disk does not fill the log */
static time_t retry_at;
static time_t backoff;
#define LEASE_FILES_MAX_BACKOFF	60
#define SAVE_ERR	(retry_at != 0 ? LOG_DEBUG : LOG_ERR)
/* Set by the first lease_files_poll(): the main loop runs, so the tables are
 * complete. A shutdown before that writes nothing, and the files of the last
 * run stay as they are. */
static int running;

#define BOOT_ID_LEN	64
const char * lease_files_boot_id_path = "/proc/sys/kernel/random/boot_id";

/* The id of this boot, or NA where the system has none we read. */
static void
boot_id(char * id, size_t size)
{
	FILE * f = fopen(lease_files_boot_id_path, "r");
	size_t n;
	snprintf(id, size, "%s", LEASE_NA);
	if(f == NULL)
		return;
	if(fgets(id, (int)size, f) == NULL)
		snprintf(id, size, "%s", LEASE_NA);
	fclose(f);
	n = strcspn(id, "\r\n");
	id[n] = '\0';
	/* a word of the header: no space in it */
	if(n == 0 || strcspn(id, " \t=") != n)
		snprintf(id, size, "%s", LEASE_NA);
}

/* How a load reads an expiry: on the wall clock; on the monotonic clock of
 * the save (the same boot); or as if the save was just now (the clock never
 * got set). */
static struct {
	enum { CLOCK_UNIX, CLOCK_MONO, CLOCK_SAVE } mode;
	long long unix_time, mono;		/* of the header of .mappings */
} load_clock;
/* The load waits for the clock: it was behind the last save at startup.
 * No save runs meanwhile, or it would drop the rows of the files. So the
 * wait is short: after LEASE_FILES_CLOCK_WAIT s the rows come back with
 * the lease they had left at the save. A row of this run, which has an id
 * above held_last_id, keeps its key: the row of the file is older. */
static int held;
static time_t held_until;	/* upnp_time() */
static unsigned long long held_last_id;
static struct lease_files_restore held_restore;
#define LEASE_FILES_CLOCK_CHECK	5
#define LEASE_FILES_CLOCK_WAIT	300
/* how far the wall clock may move apart from the monotonic one in a boot,
 * by NTP slewing, for the clocks to tell a boot apart */
#define LEASE_FILES_CLOCK_SLACK	60

static int load_rows(const struct lease_files_restore * r);

static int
part_changed(enum lease_file_id id)
{
	return lease_parts[id].changes() != saved[id];
}

/* 1 if a part changed since the last save */
static int
any_changed(void)
{
	int i;
	for(i = 0; i < LF_DATA; i++)
		if(part_changed((enum lease_file_id)i))
			return 1;
	return 0;
}

/* CRC-32 (IEEE 802.3, the one of zlib and cksum -a crc32b) of n bytes,
 * going on from crc */
static unsigned long
crc32_update(unsigned long crc, const unsigned char * p, size_t n)
{
	static unsigned long table[256];
	unsigned long c;
	int i, k;

	if(table[1] == 0) {
		for(i = 0; i < 256; i++) {
			c = (unsigned long)i;
			for(k = 0; k < 8; k++)
				c = (c & 1) ? 0xedb88320UL ^ (c >> 1) : c >> 1;
			table[i] = c;
		}
	}
	crc = ~crc & 0xffffffffUL;
	while(n-- > 0)
		crc = table[(crc ^ *p++) & 0xff] ^ (crc >> 8);
	return ~crc & 0xffffffffUL;
}

/* The size and CRC-32 of the file path. 0, or -1 if it cannot be read: a
 * file which is not there has 0 and 0. */
static int
file_sum(const char * path, struct file_sum * sum)
{
	unsigned char buf[16384];
	FILE * f = fopen(path, "rb");
	size_t n;

	memset(sum, 0, sizeof(*sum));
	if(f == NULL)
		return errno == ENOENT ? 0 : -1;
	while((n = fread(buf, 1, sizeof(buf), f)) > 0) {
		sum->crc = crc32_update(sum->crc, buf, n);
		sum->bytes += n;
	}
	n = (size_t)ferror(f);
	fclose(f);
	return n ? -1 : 0;
}

/* The lines of .checksum: per data file, by its name without the dot, the
 * file on the disk and the one the save renames over it, once if they are
 * the same */
static int
same_sum(const struct file_sum * a, const struct file_sum * b)
{
	return a->bytes == b->bytes && a->crc == b->crc;
}

static void
write_checksum(FILE * f)
{
	int i;
	for(i = 0; i < LF_DATA; i++) {
		fprintf(f, "%s|%llu|%08lx\n", lease_parts[i].suffix + 1, sums[i].bytes, sums[i].crc);
		if(!same_sum(&sums_to_write[i], &sums[i]))
			fprintf(f, "%s|%llu|%08lx\n", lease_parts[i].suffix + 1,
			        sums_to_write[i].bytes, sums_to_write[i].crc);
	}
}

/* lease_file + suffix + extra. NULL if there is no memory. */
static char *
part_name(const char * suffix, const char * extra)
{
	size_t n = strlen(lease_file) + strlen(suffix) + strlen(extra) + 1;
	char * path = malloc(n);
	if(path != NULL)
		snprintf(path, n, "%s%s%s", lease_file, suffix, extra);
	return path;
}

/* Write a part to a new temporary file beside its file. Returns the name of
 * the temporary file, or NULL after an error, with nothing left behind. */
static char *
write_part(enum lease_file_id id)
{
	const struct lease_part * lp = &lease_parts[id];
	char * tmp;
	FILE * f;
	int fd, err;

	tmp = part_name(lp->suffix, LEASE_TMP "XXXXXX");
	if(tmp == NULL)
		return NULL;
	fd = mkstemp(tmp);
	if(fd < 0) {
		syslog(SAVE_ERR, "lease files: cannot create %s: %m", tmp);
		free(tmp);
		return NULL;
	}
	/* readable by the tools which show the leases */
	(void)fchmod(fd, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	f = fdopen(fd, "w");
	if(f == NULL) {
		syslog(SAVE_ERR, "lease files: fdopen %s: %m", tmp);
		close(fd);
		goto fail;
	}
	fprintf(f, "%s last_id=%llu", lp->header, lease_table_last_id());
	if(id == LF_MAPPINGS) {
		char boot[BOOT_ID_LEN + 1];
		boot_id(boot, sizeof(boot));
		fprintf(f, " boot_id=%s", boot);
	}
	/* each file its own clocks: a file is saved only when its part
	 * changed, so the files of a set may be of other saves */
	if(id != LF_CHECKSUM)
		fprintf(f, " monotonic=%lld unix=%lld", save_mono, save_unix);
	fprintf(f, "\n%s\n", lp->names);
	lp->write(f);
	/* on the disk before the rename: after a power loss, the name must
	 * not point to a file whose data never got there */
	err = fflush(f) != 0 || ferror(f) || fsync(fd) != 0;
	if(fclose(f) != 0 || err) {
		syslog(SAVE_ERR, "lease files: cannot write %s: %m", tmp);
		goto fail;
	}
	return tmp;
fail:
	unlink(tmp);
	free(tmp);
	return NULL;
}

/* Write the changed parts: all to temporary files first, then the renames,
 * .checksum first and .mappings last. A walk cannot change a count, so the
 * count after the rename is that of the file. 0, or -1 and each file is
 * either as it was or as written, as .checksum says. */
static int
save(void)
{
	char * tmp[LF_COUNT] = { NULL, NULL, NULL, NULL };
	struct file_sum next[LF_DATA];
	char * path;
	unsigned int i, n;
	int r = 0;

	save_unix = (long long)time(NULL);
	save_mono = (long long)upnp_time();
	for(i = 0; !sums_known && i < LF_DATA; i++) {
		path = part_name(lease_parts[i].suffix, "");
		if(path == NULL || file_sum(path, &sums[i]) < 0) {
			syslog(SAVE_ERR, "lease files: cannot read %s%s", lease_file, lease_parts[i].suffix);
			free(path);
			return -1;
		}
		free(path);
	}
	sums_known = 1;
	memcpy(next, sums, sizeof(next));
	for(i = 0; r == 0 && i < LF_DATA; i++) {
		if(!part_changed((enum lease_file_id)i))
			continue;
		tmp[i] = write_part((enum lease_file_id)i);
		if(tmp[i] == NULL || file_sum(tmp[i], &next[i]) < 0)
			r = -1;
	}
	/* the sums of the files as they will be once renamed */
	if(r == 0) {
		sums_to_write = next;
		tmp[LF_CHECKSUM] = write_part(LF_CHECKSUM);
		if(tmp[LF_CHECKSUM] == NULL)
			r = -1;
	}
	for(n = 0; n < LF_COUNT; n++) {
		i = (n + LF_CHECKSUM) % LF_COUNT;	/* .checksum, then the data */
		if(tmp[i] == NULL)
			continue;
		if(r == 0) {
			path = part_name(lease_parts[i].suffix, "");
			if(path == NULL)
				r = -1;
			else if(rename(tmp[i], path) < 0) {
				syslog(SAVE_ERR, "lease files: cannot rename %s: %m", tmp[i]);
				r = -1;
			} else if(i != LF_CHECKSUM) {
				saved[i] = lease_parts[i].changes();
				sums[i] = next[i];
			}
			free(path);
		}
		if(r < 0)
			unlink(tmp[i]);
		free(tmp[i]);
	}
	if(r == 0)
		syslog(LOG_DEBUG, "lease files: saved %u mappings, %u PEER bindings",
		       lease_table_count(), outgoing_table_count());
	return r;
}

void
lease_files_poll(int idle, struct timeval * timeout)
{
	time_t now, wait;

	if(lease_file == NULL)
		return;
	running = 1;
	if(held) {
		if(time(NULL) >= load_clock.unix_time) {
			syslog(LOG_NOTICE, "lease files: the clock is set, restoring");
			load_clock.mode = CLOCK_UNIX;
		} else if(upnp_time() >= held_until) {
			syslog(LOG_WARNING, "lease files: the clock is still behind the last save, "
			       "restoring with the leases left at the save");
			load_clock.mode = CLOCK_SAVE;
		} else {
			if(timeout->tv_sec > LEASE_FILES_CLOCK_CHECK) {
				timeout->tv_sec = LEASE_FILES_CLOCK_CHECK;
				timeout->tv_usec = 0;
			}
			return;
		}
		held = 0;
		(void)load_rows(&held_restore);
		held_last_id = 0;
	}
	if(!any_changed()) {
		first_change = 0;
		return;
	}
	now = upnp_time();
	if(first_change == 0)
		first_change = now;
	if(retry_at != 0 ? now >= retry_at
	   : ((idle && now >= last_save + LEASE_FILES_MIN_GAP)
	      || now >= first_change + LEASE_FILES_MAX_DELAY)) {
		int r = save();
		/* the gap counts from the end of a save: a long one does not
		 * run again at once */
		last_save = now = upnp_time();
		if(r == 0) {
			if(retry_at != 0)
				syslog(LOG_NOTICE, "lease files: saved again");
			retry_at = 0;
			backoff = 0;
			first_change = 0;
			return;
		}
		backoff = backoff == 0 ? LEASE_FILES_MAX_DELAY : 2 * backoff;
		if(backoff > LEASE_FILES_MAX_BACKOFF)
			backoff = LEASE_FILES_MAX_BACKOFF;
		retry_at = now + backoff;
	}
	if(retry_at != 0) {
		wait = retry_at - now;
	} else {
		/* wake up when the gap is over: a select() which then finds
		 * nothing to answer is idle. At the latest when the delay is
		 * over. */
		wait = last_save + LEASE_FILES_MIN_GAP - now;
		if(wait > first_change + LEASE_FILES_MAX_DELAY - now)
			wait = first_change + LEASE_FILES_MAX_DELAY - now;
	}
	if(wait < 0)
		wait = 0;
	if(timeout->tv_sec > wait) {
		timeout->tv_sec = wait;
		timeout->tv_usec = 0;
	}
}

int
lease_files_flush(void)
{
	if(lease_file == NULL || !running || held || !any_changed())
		return 0;
	return save();
}

/* The load. */

/* An id or a map field above this is bad: the table never comes near it,
 * and a reserve of it could make ++last_id wrap to 0 */
#define LEASE_ID_MAX	0x7fffffffffffffffULL

/* A line of any length, without its end of line, in *buf of *size bytes.
 * 1, or 0 at the end of the file or when there is no memory. */
static int
read_line(FILE * f, char ** buf, size_t * size)
{
	size_t n = 0;

	for(;;) {
		if(*size - n < 2) {
			size_t sz = *size ? *size * 2 : 256;
			char * p = realloc(*buf, sz);
			if(p == NULL) {
				syslog(LOG_ERR, "lease files: no memory for a line");
				return 0;
			}
			*buf = p;
			*size = sz;
		}
		if(fgets(*buf + n, (int)(*size - n), f) == NULL)
			break;
		n += strlen(*buf + n);
		if(n > 0 && (*buf)[n - 1] == '\n')
			break;
	}
	if(n == 0)
		return 0;
	while(n > 0 && ((*buf)[n - 1] == '\n' || (*buf)[n - 1] == '\r'))
		(*buf)[--n] = '\0';
	return 1;
}

/* Cut a line into its fields at each | which no \ escapes. The number of
 * fields, or -1 for more than max. */
static int
split_fields(char * line, char ** field, int max)
{
	int n = 0;
	char * p = line;

	field[n++] = p;
	while(*p) {
		if(*p == '\\' && p[1] != '\0') {
			p += 2;
		} else if(*p == LEASE_SEP) {
			*p++ = '\0';
			if(n >= max)
				return -1;
			field[n++] = p;
		} else
			p++;
	}
	return n;
}

static int
hex_digit(char c)
{
	if(c >= '0' && c <= '9')
		return c - '0';
	if(c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if(c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

/* Undo put_label() in place. NA is no label: "". -1 for a bad escape. */
static int
get_label(char * s)
{
	char * d = s;
	const char * p = s;

	if(strcmp(s, LEASE_NA) == 0) {
		s[0] = '\0';
		return 0;
	}
	while(*p) {
		if(*p != '\\') {
			*d++ = *p++;
			continue;
		}
		p++;
		switch(*p) {
		case '\\':
		case LEASE_SEP:
			*d++ = *p++;
			break;
		case 'n':
			*d++ = '\n';
			p++;
			break;
		case 'r':
			*d++ = '\r';
			p++;
			break;
		case 'x':
			if(hex_digit(p[1]) < 0 || hex_digit(p[2]) < 0)
				return -1;
			*d++ = (char)(hex_digit(p[1]) * 16 + hex_digit(p[2]));
			p += 3;
			break;
		default:
			return -1;
		}
	}
	*d = '\0';
	return 0;
}

/* A number of the whole field, at most max. 0, or -1. */
static int
get_number(const char * s, unsigned long long max, unsigned long long * v)
{
	char * end;
	if(s == NULL || *s < '0' || *s > '9')
		return -1;
	*v = strtoull(s, &end, 10);
	return (*end != '\0' || *v > max) ? -1 : 0;
}

/* An address of family, as a row has it. NA : ::. 0, or -1. */
static int
get_addr(int family, const char * s, struct in6_addr * a)
{
	memset(a, 0, sizeof(*a));
	if(s == NULL)
		return -1;
	if(strcmp(s, LEASE_NA) == 0)
		return 0;
	return map_ipv4_to_ipv6_af(s, family, a);
}

/* A PCP nonce of 24 hex digits. 0, or -1. */
static int
get_nonce(const char * h, unsigned char * nonce)
{
	int i;
	if(h == NULL || strlen(h) != 2 * MAP_NONCE_LEN)
		return -1;
	for(i = 0; i < MAP_NONCE_LEN; i++) {
		if(hex_digit(h[2 * i]) < 0 || hex_digit(h[2 * i + 1]) < 0)
			return -1;
		nonce[i] = (unsigned char)(hex_digit(h[2 * i]) * 16 + hex_digit(h[2 * i + 1]));
	}
	return 0;
}

/* The fields a reader knows, by name. A file may have more, in any order:
 * they are skipped. One it lacks has its default. */
enum {
	F_ID, F_KIND, F_FAMILY, F_PROTO, F_EPORT, F_IPORT, F_IADDR, F_EADDR,
	F_NONCE, F_EXPIRY, F_FILTERS, F_LABEL,
	F_MAP, F_RADDR, F_RPREFIX, F_RPORT, F_UID,
	F_FILE, F_BYTES, F_CRC32, F_COUNT
};
static const char * const field_names[F_COUNT] = {
	"id", "kind", "family", "proto", "eport", "iport", "iaddr", "eaddr",
	"nonce", "expiry", "filters", "label",
	"map", "raddr", "rprefix", "rport", "uid",
	"file", "bytes", "crc32"
};
#define LEASE_MAX_FIELDS	64

/* A file of the set, read up to its first line of data. */
struct lease_in {
	FILE * f;
	char * path;
	int col[F_COUNT];	/* the place of each field, -1 : none */
	int ncols;
	unsigned long long last_id;	/* of the header, 0 if it lacks it */
	char boot_id[BOOT_ID_LEN + 1];	/* of .mappings, "" if it lacks it */
	int has_clock;			/* monotonic and unix are there */
	long long mono, unix_time;
	unsigned long line;
	char * buf;
	size_t size;
};

static void
in_close(struct lease_in * in)
{
	if(in->f != NULL)
		fclose(in->f);
	free(in->path);
	free(in->buf);
	memset(in, 0, sizeof(*in));
}

/* Read the header line in in->buf: the header of lp, then name=value
 * words. A word it does not know is skipped. 0, or -1 if it is not the
 * header of lp or a known word is bad. */
static int
get_header(struct lease_in * in, const struct lease_part * lp)
{
	size_t n = strlen(lp->header);
	char * p, * word, * value, * end;
	int mono = 0, unix_ok = 0;

	if(strncmp(in->buf, lp->header, n) != 0 || (in->buf[n] != '\0' && in->buf[n] != ' '))
		return -1;
	for(p = in->buf + n; *p != '\0'; ) {
		while(*p == ' ')
			p++;
		if(*p == '\0')
			break;
		word = p;
		p += strcspn(p, " ");
		if(*p != '\0')
			*p++ = '\0';
		value = strchr(word, '=');
		if(value == NULL)
			continue;
		*value++ = '\0';
		if(strcmp(word, "last_id") == 0) {
			if(get_number(value, LEASE_ID_MAX, &in->last_id) < 0)
				return -1;
		} else if(strcmp(word, "boot_id") == 0) {
			if(strlen(value) > BOOT_ID_LEN)
				return -1;
			snprintf(in->boot_id, sizeof(in->boot_id), "%s", value);
		} else if(strcmp(word, "monotonic") == 0) {
			in->mono = strtoll(value, &end, 10);
			if(end == value || *end != '\0')
				return -1;
			mono = 1;
		} else if(strcmp(word, "unix") == 0) {
			in->unix_time = strtoll(value, &end, 10);
			if(end == value || *end != '\0')
				return -1;
			unix_ok = 1;
		}
	}
	in->has_clock = mono && unix_ok;
	return 0;
}

/* Open a file of the set and read its header and its field names. 1, 0 if
 * there is no such file, or -1 if it is not one of ours, of this version:
 * logged unless quiet. */
static int
in_open(struct lease_in * in, enum lease_file_id id, int quiet)
{
	const struct lease_part * lp = &lease_parts[id];
	char * names[LEASE_MAX_FIELDS];
	int i, j;

	memset(in, 0, sizeof(*in));
	for(i = 0; i < F_COUNT; i++)
		in->col[i] = -1;
	in->path = part_name(lp->suffix, "");
	if(in->path == NULL)
		return -1;
	in->f = fopen(in->path, "r");
	if(in->f == NULL)
		return 0;
	if(!read_line(in->f, &in->buf, &in->size) || get_header(in, lp) < 0)
		goto bad;
	if(!read_line(in->f, &in->buf, &in->size))
		goto bad;
	in->line = 2;
	in->ncols = split_fields(in->buf, names, LEASE_MAX_FIELDS);
	if(in->ncols < 0)
		goto bad;
	for(i = 0; i < in->ncols; i++)
		for(j = 0; j < F_COUNT; j++)
			if(strcmp(names[i], field_names[j]) == 0 && in->col[j] < 0)
				in->col[j] = i;
	return 1;
bad:
	if(!quiet)
		syslog(LOG_ERR, "lease files: %s has an unknown header", in->path);
	return -1;
}

/* Keep a set which is not ours, or does not match its checksums, out of
 * the way: the next save would overwrite it. Each file of the set there is
 * becomes <name>.bad. */
static void
set_aside_all(void)
{
	char * path, * bad;
	int i;
	sums_known = 0;		/* the files are gone: read the sums again */
	for(i = 0; i < LF_COUNT; i++) {
		path = part_name(lease_parts[i].suffix, "");
		bad = part_name(lease_parts[i].suffix, ".bad");
		if(path != NULL && bad != NULL && access(path, F_OK) == 0) {
			if(rename(path, bad) == 0)
				syslog(LOG_WARNING, "lease files: renamed %s to %s", path, bad);
			else
				syslog(LOG_ERR, "lease files: cannot rename %s: %m", path);
		}
		free(path);
		free(bad);
	}
}

/* The next line of data, cut into fields: field[F_*] is NULL for a field the
 * file lacks. 1, or 0 at the end. A line with another number of fields is
 * logged and skipped. */
static int
in_next(struct lease_in * in, char ** field)
{
	char * cols[LEASE_MAX_FIELDS];
	int i, n;

	while(read_line(in->f, &in->buf, &in->size)) {
		in->line++;
		if(in->buf[0] == '\0')
			continue;
		n = split_fields(in->buf, cols, LEASE_MAX_FIELDS);
		if(n != in->ncols) {
			syslog(LOG_WARNING, "lease files: %s:%lu: %d fields, not %d, skipped",
			       in->path, in->line, n, in->ncols);
			continue;
		}
		for(i = 0; i < F_COUNT; i++)
			field[i] = in->col[i] >= 0 ? cols[in->col[i]] : NULL;
		return 1;
	}
	return 0;
}

/* Log a bad field of the current line. 0: the line is skipped. */
static int
bad_line(const struct lease_in * in, const char * what)
{
	syslog(LOG_WARNING, "lease files: %s:%lu: bad %s, skipped", in->path, in->line, what);
	return 0;
}

/* The family, protocol and expiry of a line, common to .mappings and
 * .outgoing. The expiry goes on the clock of upnp_time(). 1, or 0 to skip
 * the line (logged). */
static int
get_common(struct lease_in * in, char ** field, unsigned char * family,
           unsigned char * proto, unsigned int * timestamp)
{
	unsigned long long v;
	long long t, su, sm;
	int p;

	if(field[F_FAMILY] != NULL && strcmp(field[F_FAMILY], "IPv4") == 0)
		*family = AF_INET;
	else if(field[F_FAMILY] != NULL && strcmp(field[F_FAMILY], "IPv6") == 0)
		*family = AF_INET6;
	else
		return bad_line(in, "family");
	/* as put_proto() writes it: a number, or a name which reads back */
	if(get_number(field[F_PROTO], 255, &v) == 0)
		*proto = (unsigned char)v;
	else if(field[F_PROTO] != NULL
	        && strcmp(proto_itoa(p = proto_atoi(field[F_PROTO])), field[F_PROTO]) == 0)
		*proto = (unsigned char)p;
	else
		return bad_line(in, "proto");
	*timestamp = 0;
	if(field[F_EXPIRY] == NULL)
		return 1;
	if(get_number(field[F_EXPIRY], 0xffffffffULL, &v) < 0)
		return bad_line(in, "expiry");
	if(v == 0)
		return 1;
	/* the clocks of the save of this file, else those of .mappings */
	su = in->has_clock ? in->unix_time : load_clock.unix_time;
	sm = in->has_clock ? in->mono : load_clock.mono;
	/* the same boot: on the monotonic clock of the save, which a wrong
	 * wall clock does not move */
	if(load_clock.mode == CLOCK_MONO)
		t = sm + ((long long)v - su);
	else if(load_clock.mode == CLOCK_SAVE)
		t = (long long)upnp_time() + ((long long)v - su);
	else
		t = (long long)upnp_time() + ((long long)v - (long long)time(NULL));
	if(t <= (long long)upnp_time()) {
		syslog(LOG_INFO, "lease files: %s:%lu: expired, not restored", in->path, in->line);
		return 0;
	}
	*timestamp = (unsigned int)t;
	return 1;
}

/* A line of .filters: the row it belongs to, by its id, and the filter.
 * rprefix as written, -1 : none; the family of the row tells its range. */
struct side_line {
	unsigned long long map;
	int rprefix;
	struct map_filter f;
};

struct side_lines {
	struct side_line * v;
	size_t n, size;
};

static int
cmp_side(const void * a, const void * b)
{
	const struct side_line * x = a, * y = b;
	return x->map < y->map ? -1 : x->map > y->map;
}

/* Read the lines of .filters, sorted by the id of their row. A file which
 * is not there has no lines. 0, or -1 for a bad header or no memory. */
static int
read_filters(struct side_lines * s, struct lease_in * in)
{
	char * field[F_COUNT];
	unsigned long long v;
	struct side_line l;
	int family, r;

	memset(s, 0, sizeof(*s));
	r = in_open(in, LF_FILTERS, 0);
	if(r <= 0)
		return r;
	while(in_next(in, field)) {
		memset(&l, 0, sizeof(l));
		if(get_number(field[F_MAP], LEASE_ID_MAX, &l.map) < 0 || l.map == 0) {
			(void)bad_line(in, "map");
			continue;
		}
		/* the family is that of the address; NA is any remote */
		family = field[F_RADDR] != NULL && strchr(field[F_RADDR], ':') ? AF_INET6 : AF_INET;
		if(get_addr(family, field[F_RADDR], &l.f.raddr) < 0) {
			(void)bad_line(in, "raddr");
			continue;
		}
		l.rprefix = -1;
		if(field[F_RPREFIX] != NULL) {
			/* NA has no family: the row checks the range */
			if(get_number(field[F_RPREFIX],
			              family == AF_INET && !IN6_IS_ADDR_UNSPECIFIED(&l.f.raddr) ? 32 : 128,
			              &v) < 0) {
				(void)bad_line(in, "rprefix");
				continue;
			}
			l.rprefix = (int)v;
		}
		if(field[F_RPORT] != NULL) {
			if(get_number(field[F_RPORT], 65535, &v) < 0) {
				(void)bad_line(in, "rport");
				continue;
			}
			l.f.rport = (unsigned short)v;
		}
		if(field[F_UID] != NULL && strcmp(field[F_UID], LEASE_NA) != 0) {
			if(get_number(field[F_UID], 65535, &v) < 0) {
				(void)bad_line(in, "uid");
				continue;
			}
			l.f.uid = (unsigned short)v;
		}
		if(s->n == s->size) {
			size_t sz = s->size ? s->size * 2 : 64;
			struct side_line * p = realloc(s->v, sz * sizeof(*p));
			if(p == NULL) {
				syslog(LOG_ERR, "lease files: no memory for %s", in->path);
				return -1;
			}
			s->v = p;
			s->size = sz;
		}
		s->v[s->n++] = l;
	}
	if(s->n > 1)
		qsort(s->v, s->n, sizeof(s->v[0]), cmp_side);
	return 0;
}

/* The lines of the row id, and their number. */
static const struct side_line *
side_of(const struct side_lines * s, unsigned long long id, size_t * count)
{
	struct side_line key;
	const struct side_line * p, * first, * end = s->v + s->n;

	*count = 0;
	if(s->n == 0)
		return NULL;
	key.map = id;
	p = bsearch(&key, s->v, s->n, sizeof(s->v[0]), cmp_side);
	if(p == NULL)
		return NULL;
	for(first = p; first > s->v && first[-1].map == id; first--)
		;
	for(p = first; p < end && p->map == id; p++)
		(*count)++;
	return first;
}

/* The row of a line of .mappings, into r, a request on the stack, and the
 * number of its filters. 1, or 0 to skip the line (logged). */
static int
get_mapping(struct lease_in * in, char ** field, struct lease_entry * r,
            unsigned long * nfilters)
{
	unsigned long long v;
	unsigned int i;

	*nfilters = 0;
	for(i = 0; i < KIND_NAMES; i++)
		if(field[F_KIND] != NULL && strcmp(field[F_KIND], kind_names[i].name) == 0)
			break;
	if(i == KIND_NAMES)
		return bad_line(in, "kind");
	lease_entry_init(r, kind_names[i].kind, NULL);
	if(get_number(field[F_ID], LEASE_ID_MAX, &r->id) < 0 || r->id == 0)
		return bad_line(in, "id");
	if(!get_common(in, field, &r->family, &r->proto, &r->timestamp))
		return 0;
	if(get_number(field[F_IPORT], 65535, &v) < 0)
		return bad_line(in, "iport");
	r->iport = (unsigned short)v;
	if(get_number(field[F_EPORT], 65535, &v) < 0)
		return bad_line(in, "eport");
	r->eport = (unsigned short)v;
	if(get_addr(r->family, field[F_IADDR], &r->iaddr) < 0 ||
	   IN6_IS_ADDR_UNSPECIFIED(&r->iaddr))
		return bad_line(in, "iaddr");
	if(field[F_EADDR] != NULL && get_addr(r->family, field[F_EADDR], &r->eaddr) < 0)
		return bad_line(in, "eaddr");
	if(r->kind == MAP_KIND_PCP && get_nonce(field[F_NONCE], r->nonce) < 0)
		return bad_line(in, "nonce");
	if(field[F_FILTERS] != NULL) {
		if(get_number(field[F_FILTERS], 0xffffUL, &v) < 0)
			return bad_line(in, "filters");
		*nfilters = (unsigned long)v;
	}
	if(field[F_LABEL] != NULL) {
		if(get_label(field[F_LABEL]) < 0)
			return bad_line(in, "label");
		if(field[F_LABEL][0] != '\0')
			r->label = field[F_LABEL];
	}
	return 1;
}

/* The binding of one peer of a line of .outgoing, into b, which has room
 * for one. 1, or 0 to skip the line (logged). */
static int
get_peer(struct lease_in * in, char ** field, struct outgoing_entry * b)
{
	unsigned long long v;

	if(!get_common(in, field, &b->family, &b->proto, &b->peers[0].timestamp))
		return 0;
	if(get_addr(b->family, field[F_IADDR], &b->iaddr) < 0 ||
	   IN6_IS_ADDR_UNSPECIFIED(&b->iaddr))
		return bad_line(in, "iaddr");
	if(get_number(field[F_IPORT], 65535, &v) < 0)
		return bad_line(in, "iport");
	b->iport = (unsigned short)v;
	if(get_addr(b->family, field[F_EADDR], &b->eaddr) < 0)
		return bad_line(in, "eaddr");
	if(get_number(field[F_EPORT], 65535, &v) < 0 || v == 0)
		return bad_line(in, "eport");
	b->eport = (unsigned short)v;
	if(get_nonce(field[F_NONCE], b->nonce) < 0)
		return bad_line(in, "nonce");
	if(get_addr(b->family, field[F_RADDR], &b->peers[0].raddr) < 0 ||
	   IN6_IS_ADDR_UNSPECIFIED(&b->peers[0].raddr))
		return bad_line(in, "raddr");
	if(get_number(field[F_RPORT], 65535, &v) < 0 || v == 0)
		return bad_line(in, "rport");
	b->peers[0].rport = (unsigned short)v;
	if(field[F_LABEL] != NULL) {
		if(get_label(field[F_LABEL]) < 0)
			return bad_line(in, "label");
		if(field[F_LABEL][0] != '\0')
			b->label = field[F_LABEL];
	}
	return 1;
}

/* 1 if name is <file><suffix>.tmp.XXXXXX, a temporary file of a save */
static int
is_temp_name(const char * name, const char * file, const char * suffix)
{
	size_t n = strlen(file), m = strlen(suffix), t = strlen(LEASE_TMP), i;
	if(strncmp(name, file, n) != 0 || strncmp(name + n, suffix, m) != 0 ||
	   strncmp(name + n + m, LEASE_TMP, t) != 0)
		return 0;
	name += n + m + t;
	/* the characters mkstemp() puts there */
	for(i = 0; name[i] != '\0'; i++)
		if(!((name[i] >= '0' && name[i] <= '9') || (name[i] >= 'a' && name[i] <= 'z') ||
		     (name[i] >= 'A' && name[i] <= 'Z')))
			return 0;
	return i == 6;
}

/* Remove the temporary files of a save a crash cut short:
 * <name><suffix>.tmp.XXXXXX beside each file of the set. */
static void
remove_temp_files(void)
{
	const char * slash = strrchr(lease_file, '/');
	const char * name = slash != NULL ? slash + 1 : lease_file;
	size_t dlen = slash != NULL ? (size_t)(slash - lease_file) : 0;
	char dir[PATH_MAX], path[PATH_MAX];
	struct dirent * d;
	DIR * dp;
	int i;

	if(dlen >= sizeof(dir))
		return;
	if(slash == lease_file)
		snprintf(dir, sizeof(dir), "/");
	else if(slash != NULL)
		snprintf(dir, sizeof(dir), "%.*s", (int)dlen, lease_file);
	else
		snprintf(dir, sizeof(dir), ".");
	dp = opendir(dir);
	if(dp == NULL)
		return;
	while((d = readdir(dp)) != NULL) {
		for(i = 0; i < LF_COUNT; i++) {
			if(!is_temp_name(d->d_name, name, lease_parts[i].suffix))
				continue;
			if(snprintf(path, sizeof(path), "%s/%s", dir, d->d_name) >= (int)sizeof(path))
				continue;
			if(unlink(path) == 0)
				syslog(LOG_INFO, "lease files: removed %s, of a save cut short", path);
		}
	}
	closedir(dp);
}

void
lease_files_reserve_ids(void)
{
	unsigned long long max = 0;
	struct lease_in in;
	int i;

	if(lease_file == NULL)
		return;
	remove_temp_files();
	/* each file names the highest id of its save: a side file newer than
	 * .mappings has its own. The load logs a bad file */
	for(i = 0; i < LF_COUNT; i++) {
		if(in_open(&in, (enum lease_file_id)i, 1) == 1 && in.last_id > max)
			max = in.last_id;
		in_close(&in);
	}
	lease_table_reserve_ids(max);
}

/* 1 if a row a client made while the restore waited holds the key of r.
 * A row of the files is older: it does not replace it. IPv4: the external
 * port, whatever the address (the file may have none, NA); the table then
 * has the rows of the wait only, which are few. */
static int
of_this_run(const struct lease_entry * r)
{
	const struct lease_entry * row;

	if(held_last_id == 0)
		return 0;
	if(r->family == AF_INET) {
		for(row = lease_table_next_port(NULL); row != NULL; row = lease_table_next_port(row))
			if(row->id > held_last_id && row->proto == r->proto && row->eport == r->eport)
				return 1;
		return 0;
	}
	row = lease_table_find_entry(r->proto, AF_INET6, &r->iaddr, r->iport, r->iport);
	return row != NULL && row->id > held_last_id;
}

/* Before a restore waits: the uids of .filters stay theirs, a filter made
 * meanwhile gets another one */
static void
reserve_uids(void)
{
	struct lease_in in;
	struct side_lines fs;
	unsigned short max = 0;
	size_t k;

	if(read_filters(&fs, &in) == 0)
		for(k = 0; k < fs.n; k++)
			if(fs.v[k].f.uid > max)
				max = fs.v[k].f.uid;
	in_close(&in);
	free(fs.v);
	lease_table_reserve_uids(max);
}

/* Give each row of .mappings to map. */
static void
load_mappings(struct lease_in * maps, const struct side_lines * fs,
              lease_files_map_fn map, void * arg, unsigned int * done,
              unsigned int * skipped)
{
	char * field[F_COUNT];
	struct lease_entry r, * e;
	const struct side_line * l;
	unsigned long nfilters;
	size_t nf, k;

	while(in_next(maps, field)) {
		if(!get_mapping(maps, field, &r, &nfilters)) {
			(*skipped)++;
			continue;
		}
		/* .mappings is renamed last: a crash between the renames leaves it
		 * older than .filters. A row whose filter lines do not match its
		 * count is of another save: without its filters it would let in
		 * more than its client asked for */
		l = side_of(fs, r.id, &nf);
		if(nf != nfilters) {
			syslog(LOG_WARNING, "lease files: %s:%lu: %lu filters, not %lu: of another save, not restored",
			       maps->path, maps->line, (unsigned long)nf, nfilters);
			(*skipped)++;
			continue;
		}
		if(of_this_run(&r)) {
			syslog(LOG_INFO, "lease files: %s:%lu: a mapping of this run holds its port, not restored",
			       maps->path, maps->line);
			(*skipped)++;
			continue;
		}
		e = lease_table_new((int)nf);
		if(e == NULL) {
			(*skipped)++;
			continue;
		}
		e->id = r.id;
		e->kind = r.kind;
		e->family = r.family;
		e->proto = r.proto;
		memcpy(e->nonce, r.nonce, MAP_NONCE_LEN);
		e->iaddr = r.iaddr;
		e->iport = r.iport;
		e->eaddr = r.eaddr;
		e->eport = r.eport;
		e->timestamp = r.timestamp;
		e->label = r.label;
		for(k = 0; k < nf; k++) {
			e->filters[k].raddr = l[k].f.raddr;
			/* on 128 bits in memory, also for IPv4 */
			if(l[k].rprefix > (r.family == AF_INET ? 32 : 128))
				break;
			if(l[k].rprefix >= 0)
				e->filters[k].prefix = (unsigned char)map_prefix_pton(r.family, l[k].rprefix);
			else if(!IN6_IS_ADDR_UNSPECIFIED(&l[k].f.raddr))
				e->filters[k].prefix = 128;
			e->filters[k].rport = l[k].f.rport;
			e->filters[k].uid = l[k].f.uid;
		}
		if(k < nf) {
			syslog(LOG_WARNING, "lease files: %s:%lu: rprefix %d of a filter is out of range, not restored",
			       maps->path, maps->line, l[k].rprefix);
			lease_table_free(e);
			(*skipped)++;
			continue;
		}
		map(e, arg);
		(*done)++;
	}
}

/* Give each line of .outgoing to peer, as a binding of one peer. */
static void
load_outgoing(struct lease_in * out, lease_files_peer_fn peer, void * arg,
              unsigned int * done, unsigned int * skipped)
{
	char * field[F_COUNT];
	struct outgoing_entry * b;

	while(in_next(out, field)) {
		b = outgoing_table_new(1);
		if(b == NULL) {
			(*skipped)++;
			continue;
		}
		if(!get_peer(out, field, b)) {
			outgoing_table_free(b);
			(*skipped)++;
			continue;
		}
		/* a binding there is was made while the restore waited */
		if(held_last_id != 0 && outgoing_table_find(b) != NULL) {
			outgoing_table_free(b);
			(*skipped)++;
			continue;
		}
		peer(b, arg);
		(*done)++;
	}
}

/* 0 if each data file is as one of its lines of .checksum says (the file
 * before or after the save, see save()), -1 if not, or if .checksum is
 * missing or bad (logged). A file .checksum has no line for is not there. */
static int
check_sums(void)
{
	struct lease_in in;
	char * field[F_COUNT];
	struct file_sum want[LF_DATA][2], got;
	int nwant[LF_DATA];
	unsigned long long v;
	char * path, * end;
	int i, k, r;

	memset(want, 0, sizeof(want));
	memset(nwant, 0, sizeof(nwant));
	r = in_open(&in, LF_CHECKSUM, 0);
	if(r <= 0) {
		in_close(&in);
		if(r == 0)
			syslog(LOG_ERR, "lease files: %s.checksum is missing", lease_file);
		return -1;
	}
	while(in_next(&in, field)) {
		for(i = 0; i < LF_DATA; i++)
			if(field[F_FILE] != NULL && strcmp(field[F_FILE], lease_parts[i].suffix + 1) == 0)
				break;
		if(i == LF_DATA)
			continue;	/* a file this version does not know */
		if(nwant[i] == 2 || get_number(field[F_BYTES], ~0ULL, &v) < 0 ||
		   field[F_CRC32] == NULL || strlen(field[F_CRC32]) != 8) {
			(void)bad_line(&in, "sum");
			in_close(&in);
			return -1;
		}
		want[i][nwant[i]].bytes = v;
		want[i][nwant[i]].crc = strtoul(field[F_CRC32], &end, 16);
		if(*end != '\0') {
			(void)bad_line(&in, "crc32");
			in_close(&in);
			return -1;
		}
		nwant[i]++;
	}
	in_close(&in);
	for(i = 0; i < LF_DATA; i++) {
		path = part_name(lease_parts[i].suffix, "");
		r = path != NULL ? file_sum(path, &got) : -1;
		if(nwant[i] == 0)
			nwant[i] = 1;	/* 0 and 0: not there */
		for(k = 0; r == 0 && k < nwant[i] && !same_sum(&got, &want[i][k]); k++)
			;
		if(r == 0 && k == nwant[i]) {
			syslog(LOG_ERR, "lease files: %s does not match %s.checksum", path, lease_file);
			r = -1;
		}
		free(path);
		if(r < 0)
			return -1;
	}
	return 0;
}

/* 1 if this start is in the boot of the save. The boot ids tell, where the
 * system has one (Linux). Else the clocks do: in one boot the monotonic
 * clock has not gone back, and both clocks moved alike since the save. A
 * step of the wall clock of more than LEASE_FILES_CLOCK_SLACK since, or a
 * new boot, makes them differ. */
static int
same_boot(const struct lease_in * maps)
{
	char id[BOOT_ID_LEN + 1];
	long long mono = (long long)upnp_time(), unix_now = (long long)time(NULL);
	long long d;

	boot_id(id, sizeof(id));
	if(strcmp(id, LEASE_NA) != 0 && maps->boot_id[0] != '\0' &&
	   strcmp(maps->boot_id, LEASE_NA) != 0)
		return strcmp(id, maps->boot_id) == 0;
	if(mono < maps->mono)
		return 0;
	d = (unix_now - maps->unix_time) - (mono - maps->mono);
	return d >= -LEASE_FILES_CLOCK_SLACK && d <= LEASE_FILES_CLOCK_SLACK;
}

int
lease_files_load(const struct lease_files_restore * r)
{
	struct lease_in maps;
	int ret;

	if(lease_file == NULL)
		return 0;
	load_clock.mode = CLOCK_UNIX;
	/* the header only: load_rows() logs and sets aside a bad set */
	ret = in_open(&maps, LF_MAPPINGS, 1);
	if(ret == 0) {
		in_close(&maps);
		return 0;
	}
	if(ret == 1 && maps.has_clock) {
		load_clock.unix_time = maps.unix_time;
		load_clock.mono = maps.mono;
		if(same_boot(&maps)) {
			load_clock.mode = CLOCK_MONO;
		} else if((long long)time(NULL) < load_clock.unix_time) {
			/* a new boot with the clock behind the save: the expiry
			 * of each row would be too long. Wait for NTP. */
			syslog(LOG_NOTICE, "lease files: the clock is %lld s behind the last save, "
			       "the restore waits until it is set, at most %d s",
			       load_clock.unix_time - (long long)time(NULL), LEASE_FILES_CLOCK_WAIT);
			in_close(&maps);
			reserve_uids();
			held = 1;
			held_until = upnp_time() + LEASE_FILES_CLOCK_WAIT;
			held_last_id = lease_table_last_id();
			held_restore = *r;
			return 1;
		}
	}
	in_close(&maps);
	return load_rows(r);
}

/* Read the files and give their rows to r, as lease_files_load(). */
static int
load_rows(const struct lease_files_restore * r)
{
	struct lease_in maps, filters, out;
	struct side_lines fs;
	unsigned int done = 0, skipped = 0;
	int ret, rf, ro;

	memset(&filters, 0, sizeof(filters));
	memset(&out, 0, sizeof(out));
	memset(&fs, 0, sizeof(fs));
	ret = in_open(&maps, LF_MAPPINGS, 0);
	if(ret == 0) {
		/* .mappings is the record of what exists: without it, nothing */
		in_close(&maps);
		return 0;
	}
	if(lease_files_ignore_checksum)
		syslog(LOG_NOTICE, "lease files: the checksums are not checked");
	else if(ret > 0 && check_sums() < 0)
		ret = -1;
	rf = ro = 0;
	if(ret > 0) {
		rf = read_filters(&fs, &filters);
		ro = in_open(&out, LF_OUTGOING, 0);
	}
	if(ret < 0 || rf < 0 || ro < 0) {
		/* not a set this daemon can read, or not as it was written:
		 * keep the whole set, as the next save writes each file, and
		 * load nothing */
		in_close(&maps);
		in_close(&filters);
		in_close(&out);
		set_aside_all();
		ret = -1;
		goto out;
	}
	load_mappings(&maps, &fs, r->map, r->arg, &done, &skipped);
	if(ro > 0)
		load_outgoing(&out, r->peer, r->arg, &done, &skipped);
	syslog(LOG_INFO, "lease files: read %u lines to restore, %u not", done, skipped);
	if(r->done != NULL)
		r->done(r->arg);
	ret = 1;
out:
	free(fs.v);
	in_close(&maps);
	in_close(&filters);
	in_close(&out);
	return ret;
}

#else /* ENABLE_LEASEFILE */

int lease_files_ignore_checksum = 0;

void
lease_files_poll(int idle, struct timeval * timeout)
{
	(void)idle;
	(void)timeout;
}

int
lease_files_flush(void)
{
	return 0;
}

void
lease_files_reserve_ids(void)
{
}

int
lease_files_load(const struct lease_files_restore * r)
{
	(void)r;
	return 0;
}

#endif /* ENABLE_LEASEFILE */
