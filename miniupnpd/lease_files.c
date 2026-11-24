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
 * .filters and .outgoing first, .mappings last. */
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <syslog.h>
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

/* The clock of the save: unix time minus the time of upnp_time(), so every
 * expiry of a save uses the same */
static long long unix_offset;

/* An expiry on the clock of upnp_time(), as unix time in an unsigned 32-bit
 * number, the epoch time of PCP. 0 : no expiry. */
static unsigned int
unix_expiry(unsigned int expiry)
{
	long long t;
	if(expiry == 0)
		return 0;
	t = (long long)expiry + unix_offset;
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

	fprintf(f, "%llu|%s|%s|%s|%hu|%hu|", e->id, kind_name(e->kind),
	        map_family_name(e->family), proto_itoa(e->proto), e->eport, e->iport);
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
			fprintf(f, "%s|%s|", map_family_name(b->family), proto_itoa(b->proto));
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

/* The files, in the order of their rename: .mappings last, so its side files
 * are never older than it. Each with the change count of the table part it
 * holds, and its writer. */
enum lease_file_id { LF_FILTERS, LF_OUTGOING, LF_MAPPINGS, LF_COUNT };

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
};

/* The change counts of each part at the last save. They start unlike any
 * count, so the first save writes every file. */
static unsigned long saved[LF_COUNT] = {
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
	for(i = 0; i < LF_COUNT; i++)
		if(part_changed((enum lease_file_id)i))
			return 1;
	return 0;
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
	fprintf(f, "%s last_id=%llu\n%s\n", lp->header, lease_table_last_id(),
	        lp->names);
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
 * .mappings last. A walk cannot change a count, so the count after the
 * rename is that of the file. 0, or -1 and the files are as they were. */
static int
save(void)
{
	char * tmp[LF_COUNT] = { NULL, NULL, NULL };
	char * path;
	unsigned int i;
	int r = 0;

	unix_offset = (long long)time(NULL) - (long long)upnp_time();
	for(i = 0; r == 0 && i < LF_COUNT; i++) {
		if(!part_changed((enum lease_file_id)i))
			continue;
		tmp[i] = write_part((enum lease_file_id)i);
		if(tmp[i] == NULL)
			r = -1;
	}
	for(i = 0; i < LF_COUNT; i++) {
		if(tmp[i] == NULL)
			continue;
		if(r == 0) {
			path = part_name(lease_parts[i].suffix, "");
			if(path == NULL)
				r = -1;
			else if(rename(tmp[i], path) < 0) {
				syslog(SAVE_ERR, "lease files: cannot rename %s: %m", tmp[i]);
				r = -1;
			} else
				saved[i] = lease_parts[i].changes();
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
	if(lease_file == NULL || !running || !any_changed())
		return 0;
	return save();
}

#else /* ENABLE_LEASEFILE */

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

#endif /* ENABLE_LEASEFILE */
