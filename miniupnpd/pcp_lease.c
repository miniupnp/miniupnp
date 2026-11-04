/* MiniUPnP project
 * The PCP lease file : the PCP and NAT-PMP mappings, their FILTER peers and
 * the PCP PEER mappings, kept across a restart.
 * This software is subject to the conditions detailed in the LICENCE file.
 */
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <syslog.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "macros.h"
#include "upnpglobalvars.h"
#include "commonrdr.h"
#include "upnputils.h"
#include "getifaddr.h"
#include "upnpredirect.h"
#include "pcp_filter.h"
#include "pcp_lease.h"

#if defined(ENABLE_PCP) && defined(ENABLE_LEASEFILE) && defined(PCP_LEASE_SUPPORTED)

#ifdef ENABLE_UPNPPINHOLE
#include "upnppinhole.h"
#endif

#ifdef PCP_PEER
#ifdef USE_NETFILTER
#include "netfilter/iptcrdr.h"
#ifdef USE_NFTABLES
#include "netfilter_nft/nftnlrdr.h"
#endif
#elif defined(USE_PF)
#include "pf/obsdrdr.h"
#endif
#endif /* PCP_PEER */

/* The PCP lease file is <lease_file>.pcp. The lease file of the UPnP code has
 * one line per mapping and cannot hold the options of PCP (FILTER peers, nonce,
 * PREFER_FAILURE...), nor the PEER mappings, so the mappings made by PCP and
 * NAT-PMP are kept here and not in the lease files. It is interim : the day
 * the lease file format is extended the lines can move there.
 *
 * One line per mapping or peer, always 15 fields. The fields are separated by
 * '|' (IPv6 addresses contain ':'). A field which does not apply is NA. The
 * first field is the kind of line :
 *   PCP-LEASE 1
 *   kind|proto|eport|family|iaddr|iport|ifname|nonce|prefer_failure|since|expiry|eaddr|raddr|rport|label
 *   PCP-M, NAT-PMP : a MAP : IPv4 (iaddr is the internal address) or IPv6 (a
 *       pinhole, eport is iport). family is IPv4 or IPv6. since and expiry are
 *       unix times (expiry 0 : none). ifname is NA if unknown. nonce is the 24
 *       hex digits sent on the wire (NA for NAT-PMP). eaddr is the external
 *       address when the mapping was last written (for a pinhole : iaddr), it
 *       is for the user and not used to restore. raddr and rport are NA. label is the DESCRIPTION
 *       option (RFC 7220, NA if none), the last field, with \\ for a
 *       backslash, \| for a pipe, \n and \r for the line breaks and \xHH for
 *       the other control characters. A label which is really "NA" is written
 *       \x4EA.
 *   PCP-F : a peer of the filtered MAP having this nonce. raddr is
 *       addr/prefix (IPv4 : prefix 0-32, IPv6 : prefix 1-128), rport is the
 *       source port (0 : any). ifname, prefer_failure, since, expiry, eaddr
 *       and label are NA
 *   PCP-P : a PEER mapping : IPv4 (eaddr is the translated address, NA if
 *       unknown, the address of the external interface is used then) or IPv6 (a
 *       pinhole to the remote endpoint, eaddr is iaddr, eport is iport).
 *       raddr and rport are the remote peer
 * The details only the protocol layer sees (prefer_failure, since, label) are
 * kept in a table filled by pcp_lease_note_*(). since is the time the
 * mapping was first created : a renewal with the same nonce keeps it.
 * The file is rewritten after a change, at most once per
 * PCP_LEASE_SAVE_DELAY seconds (pcp_lease_changed(), pcp_lease_flush()), and
 * at shutdown. At startup the mappings are created again from it
 * (pcp_lease_load()). */

#define LEASE_HEADER		"PCP-LEASE 1"
#define LEASE_SEP		'|'
#define LEASE_LINE_MAX		1024	/* the label is at most 128 bytes, 4 with the escapes */
#define STATE_LABEL_MAX		128
#define LEASE_FIELDS		15	/* every line, with the kind of line */
#define LEASE_NA		"NA"	/* a field which does not apply */
/* the fields : */
enum { F_KIND, F_PROTO, F_EPORT, F_FAMILY, F_IADDR, F_IPORT, F_IFNAME, F_NONCE,
       F_PREFER, F_SINCE, F_EXPIRY, F_EADDR, F_RADDR, F_RPORT, F_LABEL };

struct state_entry {
	struct state_entry * next;
	struct state_entry * hnext;	/* chain of the hash bucket */
	int peer;		/* a PEER mapping, else a MAP */
	int pmp;		/* NAT-PMP, else PCP */
	int proto;
	char iaddr[INET6_ADDRSTRLEN];
	unsigned short iport;
	char raddr[INET6_ADDRSTRLEN];	/* PEER */
	unsigned short rport;		/* PEER */
	char eaddr[INET6_ADDRSTRLEN];	/* PEER : the translated address */
	char nonce[25];		/* 24 hex digits as on the wire, "-" if none */
	int prefer_failure;
	time_t since;
	char label[STATE_LABEL_MAX + 1];
	int seen;		/* found in the firewall by the last save */
};
static struct state_entry * state_entries = NULL;
/* the entries are also in a hash table on their key, as there can be many */
#define STATE_HASH_SIZE	4096
static struct state_entry * state_hash[STATE_HASH_SIZE];

static unsigned int
hash_str(unsigned int h, const char * s)
{
	while(*s)
		h = (h ^ (unsigned char)*s++) * 16777619u;
	return h;
}

static unsigned int
state_bucket(int peer, int proto, const char * iaddr, unsigned short iport,
             const char * raddr, unsigned short rport)
{
	unsigned int h = 2166136261u;
	h = (h ^ (unsigned)peer) * 16777619u;
	h = (h ^ (unsigned)proto) * 16777619u;
	h = (h ^ iport) * 16777619u;
	h = hash_str(h, iaddr);
	if(peer)
	{
		h = (h ^ rport) * 16777619u;
		h = hash_str(h, raddr);
	}
	return h % STATE_HASH_SIZE;
}

/* get the entry of a mapping, a new one (since 'since') if there is none or
 * if the mapping now has an other nonce */
static struct state_entry *
state_get(int peer, int proto, const char * iaddr, unsigned short iport,
          const char * raddr, unsigned short rport, const char * nonce,
          time_t since)
{
	struct state_entry * e;
	unsigned int b = state_bucket(peer, proto, iaddr, iport, raddr ? raddr : "", rport);
	for(e = state_hash[b]; e != NULL; e = e->hnext)
	{
		if(e->peer == peer && e->proto == proto && e->iport == iport &&
		   strcmp(e->iaddr, iaddr) == 0 &&
		   (!peer || (e->rport == rport && strcmp(e->raddr, raddr) == 0)))
			break;
	}
	if(e != NULL && strcmp(e->nonce, nonce) != 0)
	{
		/* an other mapping reuses the key */
		e->since = since;
		e->label[0] = '\0';
		e->prefer_failure = 0;
		strlcpy(e->nonce, nonce, sizeof(e->nonce));
	}
	if(e == NULL)
	{
		e = calloc(1, sizeof(*e));
		if(e == NULL)
			return NULL;
		e->peer = peer;
		e->proto = proto;
		strlcpy(e->iaddr, iaddr, sizeof(e->iaddr));
		e->iport = iport;
		if(raddr != NULL)
			strlcpy(e->raddr, raddr, sizeof(e->raddr));
		e->rport = rport;
		strlcpy(e->nonce, nonce, sizeof(e->nonce));
		e->since = since;
		e->next = state_entries;
		state_entries = e;
		e->hnext = state_hash[b];
		state_hash[b] = e;
	}
	return e;
}

static void
state_set_label(struct state_entry * e, const char * label)
{
	size_t n = 0;
	for(; label != NULL && *label && n < STATE_LABEL_MAX; label++)
		e->label[n++] = *label;
	e->label[n] = '\0';
}

/* the label as it is written in the file : \\ for a backslash, \| for the
 * separator, \n \r and \xHH for the control characters */
static void
label_escape(const char * label, char * out, size_t len)
{
	size_t n = 0;
	for(; *label && n + 5 < len; label++)
	{
		unsigned char c = (unsigned char)*label;
		if(c == '\\' || c == LEASE_SEP)
		{
			out[n++] = '\\';
			out[n++] = (char)c;
		}
		else if(c == '\n')
		{
			out[n++] = '\\'; out[n++] = 'n';
		}
		else if(c == '\r')
		{
			out[n++] = '\\'; out[n++] = 'r';
		}
		else if(c < ' ' || c == 0x7f)
		{
			n += snprintf(out + n, 5, "\\x%02x", c);
		}
		else
			out[n++] = (char)c;
	}
	out[n] = '\0';
}

/* undo label_escape() in place */
static void
label_unescape(char * s)
{
	char * w = s;
	while(*s)
	{
		if(*s == '\\' && s[1] != '\0')
		{
			s++;
			if(*s == 'n')
				*w++ = '\n';
			else if(*s == 'r')
				*w++ = '\r';
			else if(*s == 'x' && s[1] && s[2])
			{
				unsigned int v;
				if(sscanf(s + 1, "%2x", &v) == 1)
				{
					*w++ = (char)v;
					s += 2;
				}
				else
					*w++ = 'x';
			}
			else
				*w++ = *s;
			s++;
		}
		else
			*w++ = *s++;
	}
	*w = '\0';
}

/* a field of the file : NA if empty */
static const char *
na(const char * s)
{
	return (s != NULL && s[0] != '\0') ? s : LEASE_NA;
}

/* NA read from the file : empty */
static void
unna(char * s)
{
	if(strcmp(s, LEASE_NA) == 0)
		s[0] = '\0';
}

/* the fields of a line which can be NA */
static void
unna_fields(char ** fl)
{
	unna(fl[F_IFNAME]); unna(fl[F_NONCE]); unna(fl[F_EADDR]); unna(fl[F_LABEL]);
}

/* the label as written in the file : escaped, and NA if empty. A label which
 * is really "NA" is written \x4EA, so that it is not taken for none. */
static void
label_column(const char * label, char * out, size_t len)
{
	label_escape(label, out, len);
	if(out[0] == '\0')
		strlcpy(out, LEASE_NA, len);
	else if(strcmp(out, LEASE_NA) == 0)
		strlcpy(out, "\\x4EA", len);
}

/* the address of the external interface (or use_ext_ip_addr), looked up
 * once per save. Empty if unknown. */
static void
ext_eaddr(char * buf, size_t len)
{
	buf[0] = '\0';
	if(use_ext_ip_addr)
		strlcpy(buf, use_ext_ip_addr, len);
	else if(ext_if_name == NULL || getifaddr(ext_if_name, buf, (int)len, NULL, NULL) < 0)
		buf[0] = '\0';
}

/* the external address of a mapping, for the user who reads the file (it is
 * not used to restore). IPv4 : ext, the address of the external interface.
 * IPv6 : a pinhole has no translation, the external address is the internal
 * one, as in the PCP response. NA if unknown. */
static const char *
map_eaddr(const char * iaddr, const char * ext)
{
	return na(strchr(iaddr, ':') != NULL ? iaddr : ext);
}

/* The nonce is shown as it was sent on the wire (24 hex digits). The daemon
 * keeps it as 3 words in the byte order of the host, and builds the description
 * of its mappings from the words as "PCP MAP %08x%08x%08x". */
static void
nonce_str(const uint32_t * nonce, char * buf, size_t len)
{
	const unsigned char * p = (const unsigned char *)nonce;
	size_t i;
	if(nonce == NULL || len < 25)
	{
		strlcpy(buf, "-", len);
		return;
	}
	for(i = 0; i < 12; i++)
		snprintf(buf + 2 * i, 3, "%02x", p[i]);
}

/* nonce of a description "PCP MAP %08x%08x%08x" or "PCP PEER ..." */
static void
nonce_of_desc(const char * hexwords, char * buf, size_t len)
{
	unsigned int w[3];
	uint32_t n[3];
	if(sscanf(hexwords, "%8x%8x%8x", &w[0], &w[1], &w[2]) != 3)
	{
		strlcpy(buf, "-", len);
		return;
	}
	n[0] = w[0]; n[1] = w[1]; n[2] = w[2];
	nonce_str(n, buf, len);
}

/* description of a mapping from its nonce, as the daemon builds it */
static void
desc_of_nonce(const char * kind, const char * nonce, char * desc, size_t len)
{
	uint32_t n[3];
	unsigned int b;
	size_t i;
	unsigned char * p = (unsigned char *)n;
	memset(n, 0, sizeof(n));
	if(strlen(nonce) == 24)
	{
		for(i = 0; i < 12; i++)
		{
			if(sscanf(nonce + 2 * i, "%2x", &b) != 1)
				break;
			p[i] = (unsigned char)b;
		}
	}
	snprintf(desc, len, "%s %08x%08x%08x", kind,
	         (unsigned)n[0], (unsigned)n[1], (unsigned)n[2]);
}

void
pcp_lease_note_map(int pmp, int proto, const char * iaddr,
                   unsigned short iport, const uint32_t * nonce,
                   int prefer_failure, const char * label)
{
	char n[25];
	struct state_entry * e;
	nonce_str(nonce, n, sizeof(n));
	e = state_get(0, proto, iaddr, iport, NULL, 0, n, time(NULL));
	if(e == NULL)
		return;
	e->pmp = pmp;
	e->prefer_failure = prefer_failure;
	if(label != NULL)
		state_set_label(e, label);
}

void
pcp_lease_note_peer(int proto, const char * iaddr, unsigned short iport,
                    const char * raddr, unsigned short rport,
                    const char * eaddr, const uint32_t * nonce,
                    int prefer_failure, const char * label)
{
	char n[25];
	struct state_entry * e;
	nonce_str(nonce, n, sizeof(n));
	e = state_get(1, proto, iaddr, iport, raddr, rport, n, time(NULL));
	if(e == NULL)
		return;
	if(eaddr != NULL)
		strlcpy(e->eaddr, eaddr, sizeof(e->eaddr));
	e->prefer_failure = prefer_failure;
	if(label != NULL)
		state_set_label(e, label);
}

static int
state_path(char * path, size_t len)
{
	if(lease_file == NULL || strlen(lease_file) + 8 > len)
		return -1;
	snprintf(path, len, "%s.pcp", lease_file);
	return 0;
}

/* expiry of a mapping (our time) as a unix time */
static unsigned int
unix_expiry(unsigned int ts)
{
	if(ts == 0)
		return 0;
	if(ts <= upnp_time())
		return (unsigned int)time(NULL);	/* expired */
	return ts - upnp_time() + (unsigned int)time(NULL);
}

/* is desc "<prefix>" and the 24 hex digits of a nonce ? */
static int
desc_has_nonce(const char * desc, const char * prefix)
{
	size_t i, n = strlen(prefix);
	if(strncmp(desc, prefix, n) != 0 || strlen(desc) != n + 24)
		return 0;
	for(i = n; i < n + 24; i++)
	{
		if(!((desc[i] >= '0' && desc[i] <= '9') ||
		     (desc[i] >= 'a' && desc[i] <= 'f')))
			return 0;
	}
	return 1;
}

/* the pinhole of a PCP PEER (IPv6) */
static int
desc_is_peer(const char * desc)
{
	return desc_has_nonce(desc, "PCP PEER ");
}

/* is this description the one of a mapping made by PCP MAP ("PCP MAP"
 * and the 24 hex digits of the nonce) or by NAT-PMP ("NAT-PMP eport PROTO",
 * only checked if proto >= 0) ? A UPnP client could choose any text, so it
 * has to match exactly. proto < 0 : the description of a pinhole, a PCP MAP
 * or a PCP PEER. */
int
pcp_lease_owns(const char * desc, unsigned short eport, int proto)
{
	if(desc_has_nonce(desc, "PCP MAP "))
		return 1;
	if(proto < 0 && desc_is_peer(desc))
		return 1;
	if(proto >= 0 && strncmp(desc, "NAT-PMP ", 8) == 0)
	{
		char expected[64];
		snprintf(expected, sizeof(expected), "NAT-PMP %hu %s", eport, proto_itoa(proto));
		return strcmp(desc, expected) == 0;
	}
	return 0;
}

/* the PCP and NAT-PMP mappings found in the firewall */
struct save_ctx {
	struct pcp_lease_map * maps;
	unsigned int n, cap;
	unsigned int * tab;	/* hash set of the maps : index + 1, 0 is free */
	unsigned int tabsize;	/* a power of 2 */
	int error;
};

static unsigned int
map_hash(const struct pcp_lease_map * m)
{
	unsigned int h = 2166136261u;
	h = (h ^ (unsigned)m->proto) * 16777619u;
	h = (h ^ m->eport) * 16777619u;
	h = (h ^ m->iport) * 16777619u;
	return hash_str(h, m->iaddr);
}

/* put the map i of c->maps in the hash set (the table has a free slot) */
static void
map_tab_insert(struct save_ctx * c, unsigned int i)
{
	unsigned int h = map_hash(&c->maps[i]) & (c->tabsize - 1);
	while(c->tab[h] != 0)
		h = (h + 1) & (c->tabsize - 1);
	c->tab[h] = i + 1;
}

static void
save_map_cb(const struct pcp_lease_map * m, void * arg)
{
	struct save_ctx * c = arg;
	unsigned int i;
	if(c->error)
		return;
	if(!pcp_lease_owns(m->desc, m->eport, m->proto) &&
	   !(strchr(m->iaddr, ':') != NULL && desc_is_peer(m->desc)))
		return;	/* a UPnP mapping, kept by the lease file */
	if(c->tab != NULL)
	{
		for(i = map_hash(m) & (c->tabsize - 1); c->tab[i] != 0;
		    i = (i + 1) & (c->tabsize - 1))
		{
			const struct pcp_lease_map * o = &c->maps[c->tab[i] - 1];
			if(o->proto == m->proto && o->eport == m->eport &&
			   o->iport == m->iport && strcmp(o->iaddr, m->iaddr) == 0 &&
			   (!desc_is_peer(m->desc) ||
			    (o->rport == m->rport && strcmp(o->raddr, m->raddr) == 0)))
				return;	/* a mapping with a rule per peer */
		}
	}
	if(c->tab == NULL || (c->n + 1) * 2 > c->tabsize)
	{
		unsigned int size = c->tabsize ? c->tabsize * 2 : 64;
		unsigned int * t = calloc(size, sizeof(*t));
		if(t == NULL) { c->error = 1; return; }
		free(c->tab);
		c->tab = t;
		c->tabsize = size;
		for(i = 0; i < c->n; i++)
			map_tab_insert(c, i);
	}
	if(c->n == c->cap)
	{
		unsigned int cap = c->cap ? c->cap * 2 : 16;
		struct pcp_lease_map * p = realloc(c->maps, cap * sizeof(*p));
		if(p == NULL) { c->error = 1; return; }
		c->maps = p;
		c->cap = cap;
	}
	c->maps[c->n] = *m;
	map_tab_insert(c, c->n);
	c->n++;
}

/* the family column of an address */
static const char *
family_of(const char * addr)
{
	return strchr(addr, ':') != NULL ? "IPv6" : "IPv4";
}

/* the nonce column ("-" in the table of the mappings : none, NA) */
static const char *
nonce_column(const char * nonce)
{
	return strcmp(nonce, "-") == 0 ? LEASE_NA : nonce;
}

#ifdef PCP_PEER
/* write the PCP-P line of an IPv4 PEER mapping */
static void
save_peer_cb(const struct pcp_lease_peer * p, void * arg)
{
	FILE * f = arg;
	char nonce[25], label[STATE_LABEL_MAX * 4 + 1];
	struct state_entry * e;
	if(p->timestamp != 0 && p->timestamp <= upnp_time())
		return;	/* expired */
	if(strncmp(p->desc, "PCP PEER ", 9) == 0)
		nonce_of_desc(p->desc + 9, nonce, sizeof(nonce));
	else
		strlcpy(nonce, "-", sizeof(nonce));
	e = state_get(1, p->proto, p->iaddr, p->iport, p->raddr, p->rport, nonce, time(NULL));
	if(e != NULL)
		e->seen = 1;
	label_column(e ? e->label : "", label, sizeof(label));
	fprintf(f, "PCP-P|%s|%hu|IPv4|%s|%hu|%s|%s|%d|%u|%u|%s|%s|%hu|%s\n",
	        proto_itoa(p->proto), p->eport, p->iaddr, p->iport, na(p->ifname),
	        nonce_column(e ? e->nonce : "-"), e ? e->prefer_failure : 0,
	        e ? (unsigned)e->since : (unsigned)time(NULL),
	        unix_expiry(p->timestamp), na(e ? e->eaddr : ""), p->raddr, p->rport, label);
}
#endif /* PCP_PEER */

static int pcp_lease_write(void);
static int lease_pending;	/* a change is not in the file yet */
static time_t lease_last_save;	/* upnp_time() of the last save, 0 : none */

void
pcp_lease_changed(void)
{
	if(lease_last_save == 0 || upnp_time() - lease_last_save >= PCP_LEASE_SAVE_DELAY)
		pcp_lease_save();
	else
		lease_pending = 1;
}

int
pcp_lease_flush(int force, struct timeval * timeout)
{
	time_t left;
	if(!lease_pending)
		return 0;
	left = lease_last_save + PCP_LEASE_SAVE_DELAY - upnp_time();
	if(force || left <= 0)
		return pcp_lease_save();
	if(timeout != NULL && timeout->tv_sec >= left)
	{
		timeout->tv_sec = left;
		timeout->tv_usec = 0;
	}
	return 0;
}

int
pcp_lease_save(void)
{
	int r = pcp_lease_write();
	lease_last_save = upnp_time();
	lease_pending = r < 0;	/* tried again PCP_LEASE_SAVE_DELAY later */
	return r;
}

static int
pcp_lease_write(void)
{
	char path[MAXPATHLEN], tmp[MAXPATHLEN + 8];
	char ext[INET6_ADDRSTRLEN];
	struct save_ctx c;
	struct state_entry * e, ** pe;
	unsigned int i;
	FILE * f;
	if(state_path(path, sizeof(path)) < 0)
		return 0;
	memset(&c, 0, sizeof(c));
	/* never write a file without the mappings which could not be read */
	if(pcp_lease_maps(save_map_cb, &c) < 0)
		c.error = 1;
	free(c.tab);
	if(c.error)
	{
		free(c.maps);
		return -1;
	}
	snprintf(tmp, sizeof(tmp), "%s.tmp", path);
	f = fopen(tmp, "w");
	if(f == NULL)
	{
		syslog(LOG_ERR, "could not open %s: %m", tmp);
		free(c.maps);
		return -1;
	}
	ext_eaddr(ext, sizeof(ext));
	fprintf(f, "%s\n", LEASE_HEADER);
	for(i = 0; i < c.n; i++)
	{
		const struct pcp_lease_map * m = &c.maps[i];
		int pmp = m->desc[0] == 'N';
		char nonce[25], label[STATE_LABEL_MAX * 4 + 1];
		if(desc_is_peer(m->desc))
			continue;	/* a PEER pinhole : PCP-P, below */
		if(pmp)
			strlcpy(nonce, "-", sizeof(nonce));
		else
			nonce_of_desc(m->desc + 8, nonce, sizeof(nonce));
		e = state_get(0, m->proto, m->iaddr, m->iport, NULL, 0, nonce, time(NULL));
		if(e != NULL)
		{
			e->pmp = pmp;
			e->seen = 1;
		}
		label_column(e ? e->label : "", label, sizeof(label));
		fprintf(f, "%s|%s|%hu|%s|%s|%hu|%s|%s|%d|%u|%u|%s|NA|NA|%s\n",
		        pmp ? "NAT-PMP" : "PCP-M", proto_itoa(m->proto), m->eport,
		        family_of(m->iaddr), m->iaddr, m->iport, na(m->ifname),
		        nonce_column(nonce), e ? e->prefer_failure : 0,
		        e ? (unsigned)e->since : (unsigned)time(NULL),
		        unix_expiry(m->timestamp),
		        map_eaddr(m->iaddr, ext), label);
	}
	for(i = 0; i < c.n; i++)
	{
		const struct pcp_lease_map * m = &c.maps[i];
		struct pcp_filter filters[PCP_FILTER_PEER_MAX];
		struct in6_addr address;
		struct in_addr ia;
		char nonce[25];
		unsigned int k, n;
		int v4;
		if(m->desc[0] != 'P' || desc_is_peer(m->desc))
			continue;	/* only PCP has peers */
		memset(&address, 0, sizeof(address));
		v4 = inet_pton(AF_INET, m->iaddr, &ia) == 1;
		if(v4)
		{
			address.s6_addr[10] = address.s6_addr[11] = 0xff;
			memcpy(address.s6_addr + 12, &ia, 4);
		}
		else if(inet_pton(AF_INET6, m->iaddr, &address) != 1)
			continue;
		nonce_of_desc(m->desc + 8, nonce, sizeof(nonce));
		n = pcp_filter_get(&address, m->iport, m->proto, filters, PCP_FILTER_PEER_MAX);
		for(k = 0; k < n; k++)
		{
			char a[INET6_ADDRSTRLEN];
			if(v4)
				inet_ntop(AF_INET, filters[k].address.s6_addr + 12, a, sizeof(a));
			else
				inet_ntop(AF_INET6, &filters[k].address, a, sizeof(a));
			fprintf(f, "PCP-F|%s|%hu|%s|%s|%hu|NA|%s|NA|NA|NA|NA|%s/%u|%hu|NA\n",
			        proto_itoa(m->proto), m->eport, family_of(m->iaddr), m->iaddr,
			        m->iport, nonce, a,
			        v4 ? filters[k].prefix - 96u : filters[k].prefix, filters[k].port);
		}
	}
#ifdef PCP_PEER
	/* the PEER pinholes (IPv6) */
	for(i = 0; i < c.n; i++)
	{
		const struct pcp_lease_map * m = &c.maps[i];
		char nonce[25], label[STATE_LABEL_MAX * 4 + 1];
		if(!desc_is_peer(m->desc))
			continue;
		nonce_of_desc(m->desc + 9, nonce, sizeof(nonce));
		e = state_get(1, m->proto, m->iaddr, m->iport, m->raddr, m->rport,
		              nonce, time(NULL));
		if(e != NULL)
			e->seen = 1;
		label_column(e ? e->label : "", label, sizeof(label));
		fprintf(f, "PCP-P|%s|%hu|IPv6|%s|%hu|%s|%s|%d|%u|%u|%s|%s|%hu|%s\n",
		        proto_itoa(m->proto), m->eport, m->iaddr, m->iport, na(m->ifname),
		        nonce_column(nonce), e ? e->prefer_failure : 0,
		        e ? (unsigned)e->since : (unsigned)time(NULL),
		        unix_expiry(m->timestamp), m->iaddr, na(m->raddr), m->rport, label);
	}
#endif
	free(c.maps);
#ifdef PCP_PEER
	/* the IPv4 PEER mappings, in one pass over the rules */
	if(pcp_lease_peers(save_peer_cb, f) < 0)
	{
		syslog(LOG_ERR, "could not read the PEER mappings, %s not written", path);
		fclose(f);
		remove(tmp);
		for(e = state_entries; e != NULL; e = e->next)
			e->seen = 0;
		return -1;
	}
#endif
	/* forget the mappings which are gone */
	for(pe = &state_entries; *pe != NULL; )
	{
		e = *pe;
		if(!e->seen)
		{
			*pe = e->next;
			free(e);
		}
		else
		{
			e->seen = 0;
			pe = &e->next;
		}
	}
	/* the hash table is built again from the entries kept */
	memset(state_hash, 0, sizeof(state_hash));
	for(e = state_entries; e != NULL; e = e->next)
	{
		unsigned int b = state_bucket(e->peer, e->proto, e->iaddr, e->iport,
		                              e->raddr, e->rport);
		e->hnext = state_hash[b];
		state_hash[b] = e;
	}
	if(fclose(f) != 0 || rename(tmp, path) < 0)
	{
		syslog(LOG_ERR, "could not write %s: %m", path);
		return -1;
	}
	return 0;
}

/* split line at the first n-1 separators into fields[], the last one is the rest */
static int
split_fields(char * line, char ** fields, int n)
{
	int i;
	char * p = line;
	for(i = 0; i < n - 1; i++)
	{
		fields[i] = p;
		p = strchr(p, LEASE_SEP);
		if(p == NULL)
			return -1;
		*p++ = '\0';
	}
	fields[n - 1] = p;
	p += strcspn(p, "\r\n");
	*p = '\0';
	return 0;
}

/* The PCP-F lines of the file, chained by the mapping they belong to (proto,
 * iaddr, iport, nonce), in the order of the file : the file is read once and
 * not once for each mapping. */
struct filter_index {
	char ** lines;
	unsigned int nlines;
	unsigned int nbuckets;	/* a power of 2 */
	unsigned int * head;	/* line + 1 of the first PCP-F line of the bucket */
	unsigned int * next;	/* line + 1 of the next line of the bucket */
};

static unsigned int
filter_hash(const char * proto, const char * iaddr, const char * iport,
            const char * nonce)
{
	unsigned int h = 2166136261u;
	h = hash_str(h, proto);
	h = hash_str(h, iaddr);
	h = hash_str(h, iport);
	return hash_str(h, nonce);
}

static void
filter_index_free(struct filter_index * x)
{
	free(x->head);
	free(x->next);
}

/* returns <0 if out of memory (then read_filters() finds nothing) */
static int
filter_index_build(struct filter_index * x, char ** lines, unsigned int nlines)
{
	unsigned int i;
	memset(x, 0, sizeof(*x));
	x->lines = lines;
	x->nlines = nlines;
	x->nbuckets = 64;
	while(x->nbuckets < nlines)
		x->nbuckets *= 2;
	x->head = calloc(x->nbuckets, sizeof(*x->head));
	x->next = calloc(nlines ? nlines : 1, sizeof(*x->next));
	if(x->head == NULL || x->next == NULL)
	{
		filter_index_free(x);
		memset(x, 0, sizeof(*x));
		return -1;
	}
	/* backwards, so that each chain is in the order of the file */
	for(i = nlines; i-- > 0; )
	{
		char tmp[LEASE_LINE_MAX], * ff[LEASE_FIELDS];
		unsigned int b;
		if(strncmp(lines[i], "PCP-F|", 6) != 0)
			continue;
		strlcpy(tmp, lines[i], sizeof(tmp));
		if(split_fields(tmp, ff, LEASE_FIELDS) < 0)
			continue;
		b = filter_hash(ff[F_PROTO], ff[F_IADDR], ff[F_IPORT], ff[F_NONCE]) & (x->nbuckets - 1);
		x->next[i] = x->head[b];
		x->head[b] = i + 1;
	}
	return 0;
}

/* the FILTER peers of a mapping : the PCP-F lines having its nonce */
static unsigned int
read_filters(const struct filter_index * x, char ** fl, int v4,
             struct pcp_filter * filters)
{
	unsigned int i, n = 0;
	char tmp[LEASE_LINE_MAX], * ff[LEASE_FIELDS];
	if(x->head == NULL)
		return 0;
	for(i = x->head[filter_hash(fl[F_PROTO], fl[F_IADDR], fl[F_IPORT], fl[F_NONCE]) & (x->nbuckets - 1)];
	    i != 0 && n < PCP_FILTER_PEER_MAX; i = x->next[i - 1])
	{
		char * slash;
		struct pcp_filter * f = &filters[n];
		strlcpy(tmp, x->lines[i - 1], sizeof(tmp));
		if(split_fields(tmp, ff, LEASE_FIELDS) < 0)
			continue;
		if(strcmp(ff[F_PROTO], fl[F_PROTO]) != 0 || strcmp(ff[F_IADDR], fl[F_IADDR]) != 0 ||
		   strcmp(ff[F_IPORT], fl[F_IPORT]) != 0 || strcmp(ff[F_NONCE], fl[F_NONCE]) != 0)
			continue;
		slash = strchr(ff[F_RADDR], '/');
		if(slash == NULL)
			continue;
		*slash = '\0';
		memset(f, 0, sizeof(*f));
		if(v4)
		{
			f->address.s6_addr[10] = f->address.s6_addr[11] = 0xff;
			if(inet_pton(AF_INET, ff[F_RADDR], f->address.s6_addr + 12) != 1)
				continue;
			f->prefix = (unsigned char)(atoi(slash + 1) + 96);
		}
		else
		{
			if(inet_pton(AF_INET6, ff[F_RADDR], &f->address) != 1)
				continue;
			f->prefix = (unsigned char)atoi(slash + 1);
		}
		f->port = (unsigned short)atoi(ff[F_RPORT]);
		n++;
	}
	return n;
}

/* the rules of a restored mapping have to be seen by the expiry */
static void
schedule_expiry(unsigned int timestamp)
{
	if(timestamp != 0 && (nextruletoclean_timestamp == 0 ||
	                      timestamp < nextruletoclean_timestamp))
		nextruletoclean_timestamp = timestamp;
}

/* is the IPv4 redirect of this mapping still in the firewall ? */
static int
redirect_survived(unsigned short eport, int proto,
                  const char * iaddr, unsigned short iport)
{
	char iaddr_old[INET_ADDRSTRLEN];
	unsigned short iport_old;
	return get_redirect_rule(ext_if_name, eport, proto, iaddr_old, sizeof(iaddr_old),
	                         &iport_old, NULL, 0, NULL, 0, NULL, NULL, NULL) == 0 &&
	       iport_old == iport && strcmp(iaddr_old, iaddr) == 0;
}

/* create again a PCP-M or NAT-PMP mapping, with its FILTER peers :
 * (the fields are in the order of the file, see the top of this file) */
static int
restore_map(char ** fl, const struct filter_index * fx)
{
	int pmp = strcmp(fl[0], "NAT-PMP") == 0;
	int proto = proto_atoi(fl[1]);
	unsigned short eport = (unsigned short)atoi(fl[2]);
	unsigned short iport = (unsigned short)atoi(fl[5]);
	unsigned int expiry = (unsigned int)strtoul(fl[10], NULL, 10);
	long left = expiry ? (long)expiry - (long)time(NULL) : 0;
	int v4 = strcmp(fl[3], "IPv6") != 0;
	const char * ifname = ext_if_name;
	struct pcp_filter * filters = NULL;
	struct pcp_filter_update * update = NULL;
	struct in6_addr address;
	struct state_entry * e;
	unsigned int nfilters = 0;
	char desc[64];
	int r = -1;

	unna_fields(fl);
	if(pmp)
		snprintf(desc, sizeof(desc), "NAT-PMP %hu %s", eport, proto_itoa(proto));
	else
		desc_of_nonce("PCP MAP", fl[7], desc, sizeof(desc));
	if(!pcp_lease_owns(desc, eport, proto))
		return -1;
	if(expiry != 0 && left <= 0)
	{
		/* expired. Rules which survived the restart have lost their
		 * timestamp, the next expiry pass is to remove them. */
		if(v4 && redirect_survived(eport, proto, fl[4], iport) &&
		   update_portmapping_desc_timestamp(ext_if_name, eport, proto, desc,
		                                     (unsigned int)upnp_time()) == 0)
			schedule_expiry((unsigned int)upnp_time());
		return -1;
	}
	memset(&address, 0, sizeof(address));
	if(v4)
	{
		struct in_addr ia;
		if(inet_pton(AF_INET, fl[4], &ia) != 1)
			return -1;
		address.s6_addr[10] = address.s6_addr[11] = 0xff;
		memcpy(address.s6_addr + 12, &ia, 4);
	}
	else
	{
#if defined(ENABLE_UPNPPINHOLE)
		if(inet_pton(AF_INET6, fl[4], &address) != 1)
			return -1;
#ifdef ENABLE_IPV6
		if(ext_if_name6 != NULL && ext_if_name6[0] != '\0')
			ifname = ext_if_name6;
#endif
#else
		return -1;
#endif
	}
	if(fl[6][0] != '\0')
		ifname = fl[6];
	if(!pmp)
	{
		filters = malloc(PCP_FILTER_PEER_MAX * sizeof(*filters));
		if(filters == NULL)
			return -1;
		nfilters = read_filters(fx, fl, v4, filters);
		if(nfilters > 0 &&
		   pcp_filter_begin(&address, iport, proto, ifname, filters, nfilters,
		                    &update) < 0)
		{
			/* never create a filtered mapping without its filters */
			syslog(LOG_NOTICE, "Failed to restore the %u peers of PCP map %s:%hu/%s",
			       nfilters, fl[4], iport, fl[1]);
			free(filters);
			return -1;
		}
	}
	if(v4)
	{
		unsigned int timestamp = expiry ? upnp_time() + (unsigned int)left : 0;
		if(redirect_survived(eport, proto, fl[4], iport))
		{
			/* the rules are still there, their timestamp is not : it
			 * was in the memory of the previous process */
			r = update_portmapping_desc_timestamp(ext_if_name, eport, proto,
			                                      desc, timestamp);
			if(r == 0)
				schedule_expiry(timestamp);
		}
		else
			r = upnp_redirect_internal(NULL, eport, fl[4], iport, proto, desc,
			                           timestamp);
	}
#ifdef ENABLE_UPNPPINHOLE
	else
	{
		char d2[64];
		int uid = upnp_find_inboundpinhole(NULL, 0, fl[4], iport, proto,
		                                   d2, sizeof(d2), NULL);
		if(uid >= 0)
			r = upnp_update_inboundpinhole((unsigned short)uid,
			                               expiry ? (unsigned int)left : 0);
		else
			r = upnp_add_inboundpinhole(NULL, 0, fl[4], iport, proto, desc,
			                            expiry ? (unsigned int)left : 0, &uid);
	}
#endif
	if(!pmp && nfilters > 0)
		pcp_filter_finish(update, r >= 0);
	free(filters);
	if(r < 0)
		return -1;
	e = state_get(0, proto, fl[4], iport, NULL, 0, fl[7][0] ? fl[7] : "-",
	              (time_t)strtoul(fl[9], NULL, 10));
	if(e != NULL)
	{
		e->pmp = pmp;
		e->prefer_failure = atoi(fl[8]) != 0;
		label_unescape(fl[F_LABEL]);
		state_set_label(e, fl[F_LABEL]);
	}
	return nfilters;
}

#ifdef PCP_PEER
/* create again the pinhole of a PCP PEER (IPv6) : a pinhole to the remote
 * endpoint. lifetime : the time left, 0 for none. */
static int
restore_peer6(char ** fl, const char * desc, unsigned int lifetime)
{
	struct state_entry * e;
	int proto = proto_atoi(fl[F_PROTO]);
	unsigned short iport = (unsigned short)atoi(fl[F_IPORT]);
	unsigned short rport = (unsigned short)atoi(fl[F_RPORT]);
	int r = -1;
#ifdef ENABLE_UPNPPINHOLE
	char d2[64];
	int uid = upnp_find_inboundpinhole(fl[F_RADDR], rport, fl[F_IADDR], iport,
	                                   proto, d2, sizeof(d2), NULL);
	if(uid >= 0)
		r = upnp_update_inboundpinhole((unsigned short)uid, lifetime);
	else
		r = upnp_add_inboundpinhole(fl[F_RADDR], rport, fl[F_IADDR], iport,
		                            proto, (char *)desc, lifetime, &uid);
#else
	UNUSED(desc); UNUSED(lifetime);
#endif
	if(r < 0)
		return -1;
	e = state_get(1, proto, fl[F_IADDR], iport, fl[F_RADDR], rport, fl[F_NONCE],
	              (time_t)strtoul(fl[F_SINCE], NULL, 10));
	if(e != NULL)
	{
		strlcpy(e->eaddr, fl[F_EADDR], sizeof(e->eaddr));
		e->prefer_failure = atoi(fl[F_PREFER]) != 0;
		label_unescape(fl[F_LABEL]);
		state_set_label(e, fl[F_LABEL]);
	}
	return 0;
}
#endif /* PCP_PEER */

int
pcp_lease_load(void)
{
	char path[MAXPATHLEN], buf[LEASE_LINE_MAX], * fl[LEASE_FIELDS], ** lines = NULL;
	FILE * f;
	struct filter_index fx;
	unsigned int i, n = 0, cap = 0, nm = 0, nf = 0, np = 0;
	memset(&fx, 0, sizeof(fx));
	if(state_path(path, sizeof(path)) < 0)
		return 0;
	f = fopen(path, "r");
	if(f == NULL)
		return 0;	/* nothing to restore */
	while(fgets(buf, sizeof(buf), f))
	{
		if(n == cap)
		{
			char ** l = realloc(lines, (cap ? cap * 2 : 64) * sizeof(*lines));
			if(l == NULL)
				break;
			lines = l;
			cap = cap ? cap * 2 : 64;
		}
		buf[strcspn(buf, "\r\n")] = '\0';
		if((lines[n] = strdup(buf)) != NULL)
			n++;
	}
	fclose(f);
	if(n == 0 || strcmp(lines[0], LEASE_HEADER) != 0)
	{
		syslog(LOG_NOTICE, "ignoring %s : unknown format", path);
		goto end;
	}
	filter_index_build(&fx, lines, n);
	for(i = 1; i < n; i++)
	{
		char tmp[LEASE_LINE_MAX];
		strlcpy(tmp, lines[i], sizeof(tmp));
		if((strncmp(tmp, "PCP-M|", 6) == 0 || strncmp(tmp, "NAT-PMP|", 8) == 0) &&
		   split_fields(tmp, fl, LEASE_FIELDS) == 0)
		{
			int r = restore_map(fl, &fx);
			if(r >= 0)
			{
				nm++;
				nf += r;
			}
		}
#ifdef PCP_PEER
		else if(strncmp(tmp, "PCP-P|", 6) == 0 &&
		        split_fields(tmp, fl, LEASE_FIELDS) == 0)
		{
			unsigned int expiry = (unsigned int)strtoul(fl[10], NULL, 10);
			long left = expiry ? (long)expiry - (long)time(NULL) : 0;
			struct state_entry * e;
			char pdesc[64];
			unsigned int timestamp;
			unna_fields(fl);
			if(expiry != 0 && left <= 0)
			{
				/* expired : remove the rule if it survived the restart */
#if defined(USE_NFTABLES) || defined(USE_PF)
				if(strcmp(fl[F_FAMILY], "IPv6") != 0)
					delete_peer_rule(fl[4], (unsigned short)atoi(fl[5]),
					                 fl[12], (unsigned short)atoi(fl[13]),
					                 proto_atoi(fl[1]));
#endif
				continue;
			}
			desc_of_nonce("PCP PEER", fl[7], pdesc, sizeof(pdesc));
			if(strcmp(fl[F_FAMILY], "IPv6") == 0)
			{
				if(restore_peer6(fl, pdesc, expiry ? (unsigned int)left : 0) == 0)
					np++;
				continue;
			}
			timestamp = expiry ? upnp_time() + (unsigned int)left : 0;
			if(add_peer_redirect_rule2(fl[6][0] ? fl[6] : ext_if_name,
			                           fl[12], (unsigned short)atoi(fl[13]),
			                           fl[11][0] ? fl[11] : NULL, /* else the address of the interface */
			                           (unsigned short)atoi(fl[2]),
			                           fl[4], (unsigned short)atoi(fl[5]),
			                           proto_atoi(fl[1]), pdesc, timestamp) == 0)
			{
				np++;
				schedule_expiry(timestamp);
			}
			e = state_get(1, proto_atoi(fl[1]), fl[4], (unsigned short)atoi(fl[5]),
			              fl[12], (unsigned short)atoi(fl[13]), fl[7],
			              (time_t)strtoul(fl[9], NULL, 10));
			if(e != NULL)
			{
				strlcpy(e->eaddr, fl[11], sizeof(e->eaddr));
				e->prefer_failure = atoi(fl[8]) != 0;
				label_unescape(fl[F_LABEL]);
				state_set_label(e, fl[F_LABEL]);
			}
		}
#endif
	}
	syslog(LOG_INFO, "Restored %u PCP and NAT-PMP mappings, %u filter peers and %u peer mappings from %s",
	       nm, nf, np, path);
end:
	filter_index_free(&fx);
	for(i = 0; i < n; i++)
		free(lines[i]);
	free(lines);
	return pcp_lease_save();
}

#elif defined(PCP_LEASE_SUPPORTED)
/* no lease file or no PCP in this build */
int pcp_lease_owns(const char * desc, unsigned short eport, int proto)
{
	UNUSED(desc); UNUSED(eport); UNUSED(proto);
	return 0;
}
void pcp_lease_note_map(int pmp, int proto, const char * iaddr,
                        unsigned short iport, const uint32_t * nonce,
                        int prefer_failure, const char * label)
{
	UNUSED(pmp); UNUSED(proto); UNUSED(iaddr); UNUSED(iport);
	UNUSED(nonce); UNUSED(prefer_failure); UNUSED(label);
}
void pcp_lease_note_peer(int proto, const char * iaddr, unsigned short iport,
                         const char * raddr, unsigned short rport,
                         const char * eaddr, const uint32_t * nonce,
                         int prefer_failure, const char * label)
{
	UNUSED(proto); UNUSED(iaddr); UNUSED(iport); UNUSED(raddr);
	UNUSED(rport); UNUSED(eaddr); UNUSED(nonce); UNUSED(prefer_failure);
	UNUSED(label);
}
int pcp_lease_save(void) { return 0; }
void pcp_lease_changed(void) { }
int pcp_lease_flush(int force, struct timeval * timeout)
{
	UNUSED(force); UNUSED(timeout);
	return 0;
}
int pcp_lease_load(void) { return 0; }
#endif

/* keep the translation unit non empty */
typedef int pcp_lease_unit_t;
