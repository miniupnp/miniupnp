/* $Id: upnppinhole.c,v 1.19 2025/04/12 23:14:30 nanard Exp $ */
/* vim: tabstop=4 shiftwidth=4 noexpandtab
 * MiniUPnP project
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * (c) 2006-2026 Thomas Bernard
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <ctype.h>
#include <unistd.h>

#include "macros.h"
#include "config.h"
#include "upnpredirect.h"
#include "memmap.h"
#include "upnpglobalvars.h"
#include "upnpevents.h"
#include "upnputils.h"
#include "upnppinhole.h"
#include "fwsync.h"
#ifdef __APPLE__
/* XXX - Apple version of PF API seems to differ from what
 * pf/pfpinhole.c expects so don't use that at least.. */
#ifdef USE_PF
#undef USE_PF
#endif /* USE_PF */
#endif /* __APPLE__ */
#if defined(USE_NETFILTER)
#include "netfilter/iptpinhole.h"
#endif
#if defined(USE_PF)
#include "pf/pfpinhole.h"
#endif
#if defined(USE_IPF)
#endif
#if defined(USE_IPFW)
#endif
#ifdef ENABLE_LEASEFILE
#include <sys/stat.h>
#endif

#ifdef ENABLE_UPNPPINHOLE

#if 0
int
upnp_check_outbound_pinhole(int proto, int * timeout)
{
	int s, tmptimeout, tmptime_out;
	switch(proto)
	{
		case IPPROTO_UDP:
			s = retrieve_timeout("udp_timeout", timeout);
			return s;
			break;
		case IPPROTO_UDPLITE:
			s = retrieve_timeout("udp_timeout_stream", timeout);
			return s;
			break;
		case IPPROTO_TCP:
			s = retrieve_timeout("tcp_timeout_established", timeout);
			return s;
			break;
		case 65535:
			s = retrieve_timeout("udp_timeout", timeout);
			s = retrieve_timeout("udp_timeout_stream", &tmptimeout);
			s = retrieve_timeout("tcp_timeout_established", &tmptime_out);
			if(tmptimeout<tmptime_out)
			{
				if(tmptimeout<*timeout)
					*timeout = tmptimeout;
			}
			else
			{
				if(tmptime_out<*timeout)
					*timeout = tmptimeout;
			}
			return s;
			break;
		default:
			return -5;
			break;
	}
	return 0;
}
#endif

#ifdef ENABLE_LEASEFILE
static int
lease_file6_add(const char * rem_client,
			   unsigned short rem_port,
               const char * int_client,
               unsigned short int_port,
               int proto,
			   int uid,
               const char * desc,
               unsigned int leaseduration)
{
	unsigned int timestamp;
	FILE * fd;

	if (lease_file6 == NULL) return 0;

	fd = fopen( lease_file6, "a");
	if (fd==NULL) {
		syslog(LOG_ERR, "could not open lease file: %s", lease_file);
		return -1;
	}

	timestamp = (leaseduration > 0) ? time(NULL) + leaseduration : 0;

	/* convert our time to unix time */
	if (timestamp != 0) {
		timestamp -= upnp_time();
	}

	fprintf(fd, "%s;%s;%hu;",
	        proto_itoa(proto), int_client, int_port);

	if (rem_client != NULL) {
		while (*rem_client) {
			if (*rem_client >= ' ' && *rem_client != ';')
				fputc(*rem_client, fd);
			rem_client++;
		}
	}

	fprintf(fd, ";%hu;%u;%u;",
	        rem_port, uid, timestamp);

	if (desc != NULL) {
		while (*desc) {
			if (*desc >= ' ')
				fputc(*desc, fd);
			desc++;
		}
	}
	fputc('\n', fd);
	fclose(fd);

	return 0;
}

/* The new expiry of the map6 of req: every line of its internal endpoint,
 * as all the filters of a map share its lease. Each line keeps its own
 * UniqueID. */
static int
lease_file6_update(const struct lease_entry * req)
{
	const unsigned int leaseduration = req->timestamp;
	char req_client[INET6_ADDRSTRLEN];
	FILE* fd, *fdt;
	char * p, * p2;
	unsigned short int_port, rem_port;
	char * proto;
	char * int_client;
	char * desc;
	char * rem_client;
	unsigned int timestamp_rule;
	unsigned int timestamp;
	char line[128];
	char tmpfilename[128];
	int uid_rule;
	int tmp;

	if (lease_file6 == NULL) return 0;
	if (map_ntop(AF_INET6, &req->iaddr, req_client, sizeof(req_client)) == NULL)
		return -1;

	if (strlen(lease_file6) + 7 > sizeof(tmpfilename)) {
		syslog(LOG_ERR, "Lease filename is too long");
		return -1;
	}

	snprintf( tmpfilename, sizeof(tmpfilename), "%sXXXXXX", lease_file6);

	fd = fopen( lease_file6, "r");
	if (fd==NULL) {
		return 0;
	}

	tmp = mkstemp(tmpfilename);
	if (tmp==-1) {
		fclose(fd);
		syslog(LOG_ERR, "could not open temporary lease file");
		return -1;
	}

	fchmod(tmp, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	fdt = fdopen(tmp, "a");

	timestamp = (leaseduration > 0) ? time(NULL) + leaseduration : 0;

	/* convert our time to unix time */
	if (timestamp != 0) {
		timestamp -= upnp_time();
	}

	while(fgets(line, sizeof(line), fd)) {

		syslog(LOG_DEBUG, "parsing lease file line '%s'", line);
		proto = line;
		p = strchr(line, ';');
		if(!p) {
			syslog(LOG_ERR, "unrecognized data in lease file");
			continue;
		}
		*(p++) = '\0';
		p2 = strchr(p, ';');
		if(!p2) {
			syslog(LOG_ERR, "unrecognized data in lease file");
			continue;
		}
		*(p2++) = '\0';
		int_port = (unsigned short)atoi(p2);
		int_client = p;
		p = strchr(p2, ';');
		if(!p) {
			syslog(LOG_ERR, "unrecognized data in lease file");
			continue;
		}
		*(p++) = '\0';
		p2 = strchr(p, ';');
		if(!p2) {
			syslog(LOG_ERR, "unrecognized data in lease file");
			continue;
		}
		*(p2++) = '\0';
		rem_port = (unsigned short)atoi(p2);
		rem_client = p;
		p = strchr(p2, ';');
		if(!p) {
			syslog(LOG_ERR, "unrecognized data in lease file");
			continue;
		}
		*(p++) = '\0';
		p2 = strchr(p, ';');
		if(!p2) {
			syslog(LOG_ERR, "unrecognized data in lease file");
			continue;
		}
		*(p2++) = '\0';
		desc = strchr(p2, ';');
		uid_rule = atoi(p);
		if(!desc) {
			syslog(LOG_ERR, "unrecognized data in lease file");
			continue;
		}
		*(desc++) = '\0';
		timestamp_rule = (unsigned int)strtoul(p2, NULL, 10);

		if (int_port == req->iport && proto_atoi(proto) == req->proto &&
		    strcmp(int_client, req_client) == 0) {
			timestamp_rule = timestamp;
		}

		desc[strcspn(desc, "\r\n")] = '\0';
		fprintf(fdt, "%s;%s;%hu;%s;%hu;%u;%u;%s\n",
	        proto, int_client, int_port, rem_client, rem_port,
	        uid_rule, timestamp_rule, desc);
	}

	fclose(fdt);
	fclose(fd);

	if (rename(tmpfilename, lease_file6) < 0) {
		syslog(LOG_ERR, "could not rename temporary lease file to %s", lease_file6);
		remove(tmpfilename);
	}

	return 0;
}

static int
lease_file6_remove(const char * int_client, unsigned short int_port, int proto, int uid)
{
	FILE* fd, *fdt;
	int tmp, uid_tmp;
	char buf[512], buf2[512];
	char str[32];
	char tmpfilename[128];
	char *p, *p2;
	int str_size, buf_size;


	if (lease_file6 == NULL) return 0;

	if (strlen(lease_file6) + 7 > sizeof(tmpfilename)) {
		syslog(LOG_ERR, "Lease filename is too long");
		return -1;
	}

	snprintf( tmpfilename, sizeof(tmpfilename), "%sXXXXXX", lease_file6);

	fd = fopen( lease_file6, "r");
	if (fd==NULL) {
		return 0;
	}

	snprintf( str, sizeof(str), "%s;%s;%u", proto_itoa(proto), int_client, int_port);
	str_size = strlen(str);

	tmp = mkstemp(tmpfilename);
	if (tmp==-1) {
		fclose(fd);
		syslog(LOG_ERR, "could not open temporary lease file");
		return -1;
	}
	fchmod(tmp, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	fdt = fdopen(tmp, "a");

	buf[sizeof(buf)-1] = 0;
	while( fgets(buf, sizeof(buf)-1, fd) != NULL) {
		buf_size = strlen(buf);

		if (uid > 0) {
			strncpy(buf2, buf, buf_size);
			// Internal Host
			p = strchr(buf2, ';');
			*(p++) = '\0';
			// Internal Port
			p = strchr(p, ';');
			*(p++) = '\0';
			// External Host
			p = strchr(p, ';');
			*(p++) = '\0';
			// External Port
			p = strchr(p, ';');
			*(p++) = '\0';
			// uid
			p = strchr(p, ';');
			*(p++) = '\0';
			p2 = strchr(p, ';');
			*(p2++) = '\0';
			uid_tmp = atoi(p);
			if (uid != uid_tmp) {
				fwrite(buf, buf_size, 1, fdt);
			}

		} else if (buf_size < str_size || strncmp(str, buf, str_size)!=0) {
			fwrite(buf, buf_size, 1, fdt);
		}
	}

	fclose(fdt);
	fclose(fd);

	if (rename(tmpfilename, lease_file6) < 0) {
		syslog(LOG_ERR, "could not rename temporary lease file to %s", lease_file6);
		remove(tmpfilename);
	}

	return 0;

}

/* At startup the table is empty, but the rule of a lease file line may
 * have outlived the daemon. It gets a row first, so that
 * upnp_add_inboundpinhole() renews it and adds no second rule. One firewall
 * read by key per line, at startup only. */
static void
reload_adopt_pinhole(const struct lease_entry * line)
{
#ifdef FW_MAP6
	struct lease_entry * e;
	u_int64_t packets;

	if(fw_map6_packets(line, 0, &packets) != 0)
		return;
	e = lease_table_copy(line);
	if(e == NULL)
		return;
	memmap_add(e);	/* the table takes e */
#else
	UNUSED(line);
#endif
}

/* reload_from_lease_file()
 * read lease_file and add the rules contained
 */
int reload_from_lease_file6(void)
{
	FILE * fd;
	char * p, * p2;
	unsigned short int_port, rem_port;
	char * proto;
	char * int_client;
	char * desc;
	char * rem_client;
	unsigned int leaseduration;
	unsigned int timestamp;
	time_t current_time;
	time_t current_unix_time;
	char line[128];
	int r, family, line_uid;
	struct lease_entry * req;

	if(!lease_file6) return -1;
	fd = fopen( lease_file6, "r");
	if (fd==NULL) {
		syslog(LOG_ERR, "could not open lease file: %s", lease_file6);
		return -1;
	}
	if(unlink(lease_file6) < 0) {
		syslog(LOG_WARNING, "could not unlink file %s : %m", lease_file6);
	}

	current_time = upnp_time();
	current_unix_time = time(NULL);

	while(fgets(line, sizeof(line), fd)) {
		syslog(LOG_DEBUG, "parsing lease file line '%s'", line);
		proto = line;
		p = strchr(line, ';');
		if(!p) {
			syslog(LOG_ERR, "unrecognized data in lease file");
			continue;
		}
		*(p++) = '\0';
		p2 = strchr(p, ';');
		if(!p2) {
			syslog(LOG_ERR, "unrecognized data in lease file");
			continue;
		}
		*(p2++) = '\0';
		int_port = (unsigned short)atoi(p2);
		int_client = p;
		p = strchr(p2, ';');
		if(!p) {
			syslog(LOG_ERR, "unrecognized data in lease file");
			continue;
		}
		*(p++) = '\0';
		p2 = strchr(p, ';');
		if(!p2) {
			syslog(LOG_ERR, "unrecognized data in lease file");
			continue;
		}
		*(p2++) = '\0';
		rem_port = (unsigned short)atoi(p2);
		rem_client = p;
		p = strchr(p2, ';');
		if(!p) {
			syslog(LOG_ERR, "unrecognized data in lease file");
			continue;
		}
		*(p++) = '\0';
		p2 = strchr(p, ';');
		if(!p2) {
			syslog(LOG_ERR, "unrecognized data in lease file");
			continue;
		}
		*(p2++) = '\0';
		line_uid = atoi(p);	/* the UniqueID of the line */
		desc = strchr(p2, ';');
		if(!desc) {
			syslog(LOG_ERR, "unrecognized data in lease file");
			continue;
		}
		*(desc++) = '\0';
		/*timestamp = (unsigned int)atoi(p2);*/
		timestamp = (unsigned int)strtoul(p2, NULL, 10);
		/* trim description */
		while(isspace(*desc))
			desc++;
		p = desc;
		while(*(p+1))
			p++;
		while(isspace(*p) && (p > desc))
			*(p--) = '\0';

		/* Ensure port is non-privileged and RemoteHost is valid */
		if (int_port < 1024) {
		    syslog(LOG_WARNING, "ignoring lease file pinhole with privileged port %hu", int_port);
		    continue;
		}
		req = lease_table_new(1);
		if (req == NULL)
			continue;
		lease_entry_set_kind(req, MAP_KIND_UPNP, NULL);
		if (map_filter_set(&req->filters[0], rem_client, rem_port) < 0 ||
		    (req->filters[0].prefix != 0 && IN6_IS_ADDR_V4MAPPED(&req->filters[0].raddr))) {
			syslog(LOG_WARNING, "ignoring lease file pinhole with invalid RemoteHost: %s", rem_client);
			lease_table_free(req);
			continue;
		}
		if (map_pton(int_client, &family, &req->iaddr) < 0 || family != AF_INET6) {
			syslog(LOG_WARNING, "ignoring lease file pinhole with invalid InternalClient: %s", int_client);
			lease_table_free(req);
			continue;
		}

		if(timestamp > 0) {
			if(timestamp <= (unsigned int)current_unix_time) {
				syslog(LOG_NOTICE, "already expired lease in lease file");
				lease_table_free(req);
				continue;
			} else {
				leaseduration = timestamp - current_unix_time;
				timestamp = leaseduration + current_time; /* convert to our time */
			}
		} else {
			leaseduration = 0;	/* default value */
		}

		req->family = AF_INET6;
		req->proto = proto_atoi(proto);
		req->iport = int_port;
		req->eaddr = req->iaddr;
		req->eport = int_port;
		lease_entry_from_desc(req, desc);
		req->timestamp = current_time + leaseduration;
		/* a UPnP pinhole keeps the UniqueID of its line, so its client
		 * can still renew and delete it, if no other has it. Else it
		 * gets a new one now: an adopted row is renewed, which gives
		 * none. */
		if(req->kind == MAP_KIND_UPNP) {
			if(line_uid > 0 && line_uid < 65535 &&
			   lease_table_find_uid((unsigned short)line_uid) == NULL)
				req->filters[0].uid = (unsigned short)line_uid;
			else
				req->filters[0].uid = lease_table_new_uid();
		}
		reload_adopt_pinhole(req);
		r = upnp_add_inboundpinhole(req, NULL);
		if(r == -1) {
			syslog(LOG_ERR, "Failed to add %s:%hu -> %s:%hu protocol %s",
			       rem_client, rem_port, int_client, int_port, proto);
		} else if(r == -2) {
			/* Add the redirection again to the lease file */
			lease_file6_add(rem_client, rem_port, int_client, int_port, proto_atoi(proto),
			               req->filters[0].uid, desc, timestamp);
		}
		if(r != 1)
			lease_table_free(req);	/* on success the lease table took it */
	}
	fclose(fd);

	return 0;
}

#endif

const struct lease_entry *
upnp_find_inboundpinhole(struct lease_entry * req)
{
	/* a request with no filter is the rule of any remote */
	static const struct map_filter any_remote;
	const struct map_filter * r = req->nfilters > 0 ? &req->filters[0] : &any_remote;
	const struct lease_entry * e;
	const struct map_filter * f = NULL;

	e = lease_table_find_entry(req->proto, AF_INET6, &req->iaddr, req->iport, req->iport);
	if(e == NULL)
		return NULL;
	if(e->nfilters > 0) {
		f = lease_filter_find(e, &r->raddr, r->prefix, r->rport);
		if(f == NULL)
			return NULL;
		/* only UPnP names a filter by a uid */
		if(req->kind == MAP_KIND_UPNP && req->nfilters > 0)
			req->filters[0].uid = f->uid;
	} else if(r->prefix != 0 || r->rport != 0) {
		return NULL;	/* a map with no filter: its one rule is of any remote */
	}
	return e;
}

#ifdef FW_MAP6
/* Add the map6 req, which upnp_add_inboundpinhole() checked: its rules,
 * its lease file line, its row. No decision is made here. 1, or -1 if the
 * firewall refused it. */
static int
upnp_add_inboundpinhole_internal(struct lease_entry * req, unsigned short * uid_out)
{
	/* a UPnP filter's uid; a PCP map has none */
	const unsigned short uid = req->nfilters > 0 ? req->filters[0].uid : 0;
	struct fw_change c;
#ifdef ENABLE_LEASEFILE
	char desc[64];
	char iaddr[INET6_ADDRSTRLEN];
	char raddr_buf[INET6_ADDRSTRLEN];
	const char * raddr = map_rhost(req, raddr_buf, sizeof(raddr_buf));
#endif

	fw_change_init(&c, FW_ADD, req, NULL);
	if (fw_sync(&c, 1) < 0) {
		if (c.applied != FW_NOT_APPLIED)
			syslog(LOG_WARNING, "map6 port %hu: a part of its rules stays", req->iport);
		return -1;
	}
#ifdef ENABLE_LEASEFILE
	map_ntop(AF_INET6, &req->iaddr, iaddr, sizeof(iaddr));
	lease_file6_add(raddr, req->nfilters > 0 ? req->filters[0].rport : 0, iaddr,
	                req->iport, req->proto, uid, map_rule_desc(req, desc, sizeof(desc)),
	                req->timestamp);
#endif /* ENABLE_LEASEFILE */
	if (uid_out != NULL)
		*uid_out = uid;
	if (req->timestamp > 0)
		next_to_clean(req->timestamp);
	memmap_add(req);	/* the table takes req */
	return 1;
}
#endif /* FW_MAP6 */

/* upnp_add_inboundpinhole()
 * The checks of an IPv6 map, as upnp_redirect() makes them for a port
 * mapping, then the add, or the renewal of the map there is.
 * returns:  1 on success
 *          -1 Pinhole space exhausted
 *          -3 the external port asked cannot be given
 *         -42 not implemented
 */
int
upnp_add_inboundpinhole(struct lease_entry * req, unsigned short * uid_out)
{
#ifdef FW_MAP6
	int r, i;
#ifdef ENABLE_LEASEFILE
	char desc_buf[64];
	const char * desc = map_rule_desc(req, desc_buf, sizeof(desc_buf));
	char iaddr[INET6_ADDRSTRLEN];
	char raddr_buf[INET6_ADDRSTRLEN];
	const char * raddr = map_rhost(req, raddr_buf, sizeof(raddr_buf));
	const unsigned short rport = req->nfilters > 0 ? req->filters[0].rport : 0;
#endif

	/* An IPv6 map has no translation: its external port is its internal
	 * port. A request which wants another port or none (PCP
	 * PREFER_FAILURE, RFC 6887 section 13.2) fails before anything
	 * changes, also a renewal; any other gets its internal port. */
	if((req->flags & MAP_PREFER_FAILURE) && req->eport != 0 && req->eport != req->iport) {
		syslog(LOG_INFO, "map6 port %hu %s: external port %hu asked, an IPv6 map has "
		       "no translation", req->iport, proto_itoa(req->proto), req->eport);
		return -3;
	}
	req->eport = req->iport;
	if(upnp_find_inboundpinhole(req) != NULL) {
		/* a UPnP filter's uid; a PCP map has none */
		const unsigned short uid = req->nfilters > 0 ? req->filters[0].uid : 0;

		syslog(LOG_INFO, "map6 port %hu %s found, renewing it",
		       req->iport, proto_itoa(req->proto));
		r = upnp_update_inboundpinhole(req, uid);
		if (r < 0)
			return r;
#ifdef ENABLE_LEASEFILE
		/* the line of the filter again: a reload, which unlinked the
		 * file, renews the rows it adopted this way */
		map_ntop(AF_INET6, &req->iaddr, iaddr, sizeof(iaddr));
		if (uid != 0)
			lease_file6_remove("*", 0, 0, uid);
		else
			lease_file6_remove(iaddr, req->iport, req->proto, -1);
		lease_file6_add(raddr, rport, iaddr, req->iport, req->proto,
		                uid, desc, req->timestamp);
#endif /* ENABLE_LEASEFILE */
		if (uid_out != NULL)
			*uid_out = uid;
		memmap_update(req, req->iport);	/* the table takes req */
		return 1;
	}
	if (max_filters_per_map >= 0) {
		/* the filters the map of the endpoint would have */
		const struct lease_entry * e = lease_table_find_entry(req->proto, AF_INET6,
		                                   &req->iaddr, req->iport, req->iport);
		int n = e != NULL ? e->nfilters : 0;
		for (i = 0; i < req->nfilters; i++) {
			const struct map_filter * f = &req->filters[i];
			if (e == NULL || lease_filter_find(e, &f->raddr, f->prefix, f->rport) == NULL)
				n++;
		}
		if (n > max_filters_per_map) {
			syslog(LOG_NOTICE, "map6 port %hu %s: %d filters, max_filters_per_map is %d",
			       req->iport, proto_itoa(req->proto), n, max_filters_per_map);
			return -1;
		}
	}
	/* A UPnP filter gets its UniqueID from the table, which knows every
	 * one in use. PCP uses none, so it is not capped by them. */
	for(i = 0; req->kind == MAP_KIND_UPNP && i < req->nfilters; i++) {
		struct map_filter * f = &req->filters[i];
		if(f->uid == 0 || lease_table_find_uid(f->uid) != NULL)
			f->uid = lease_table_new_uid();
		if(f->uid == 0) {
			syslog(LOG_WARNING, "every pinhole UniqueID is in use");
			return -1;
		}
	}
	return upnp_add_inboundpinhole_internal(req, uid_out);
#else
	UNUSED(req); UNUSED(uid_out);
	return -42;	/* not implemented */
#endif
}

/* upnp_get_pinhole_info()
 * return values :
 *   0   OK
 *  -1   Internal error
 *  -2   NOT FOUND (no such entry)
 *  ..
 *  -42  Not implemented
 */
int
upnp_get_pinhole_info(unsigned short uid,
                      char * raddr, int raddrlen,
                      unsigned short * rport,
                      char * iaddr, int iaddrlen,
                      unsigned short * iport,
                      int * proto, char * desc, int desclen,
                      unsigned int * leasetime,
                      unsigned int * packets)
{
	const struct map_filter * f = lease_table_find_uid(uid);
	const struct lease_entry * e;
	char desc_buf[64];
	unsigned int now;

	if(f == NULL)
		return -2;
	e = f->map;
	if(raddr && raddrlen > 0) {
		raddr[0] = '\0';
		if(f->prefix != 0)
			map_ntop(AF_INET6, &f->raddr, raddr, (size_t)raddrlen);
	}
	if(rport)
		*rport = f->rport;
	if(iaddr && iaddrlen > 0 &&
	   map_ntop(AF_INET6, &e->iaddr, iaddr, (size_t)iaddrlen) == NULL)
		iaddr[0] = '\0';
	if(iport)
		*iport = e->iport;
	if(proto)
		*proto = e->proto;
	if(desc && desclen > 0)
		snprintf(desc, (size_t)desclen, "%s", map_rule_desc(e, desc_buf, sizeof(desc_buf)));
	if(leasetime) {
		now = (unsigned int)upnp_time();
		*leasetime = e->timestamp > now ? e->timestamp - now : 0;
	}
	if(packets) {
		/* the counter of the rule: only the firewall has it */
#ifdef FW_MAP6
		u_int64_t packets_tmp;
		if(fw_map6_packets(e, (int)(f - e->filters), &packets_tmp) < 0)
			return -1;
		*packets = (unsigned int)packets_tmp;
#else
		return -42;	/* not implemented */
#endif
	}
	return 0;
}

int
upnp_update_inboundpinhole(const struct lease_entry * req, unsigned short uid)
{
#ifdef FW_MAP6
	const struct lease_entry * e = NULL;
	const struct map_filter * f;

	/* UpdatePinhole names the pinhole by its UniqueID alone; PCP by the
	 * key of its filter */
	if(uid != 0) {
		f = lease_table_find_uid(uid);
		if(f != NULL)
			e = f->map;
	} else {
		e = upnp_find_inboundpinhole((struct lease_entry *)req);
	}
	if(e == NULL)
		return -1;
	/* The rule holds no expiry: a renewal changes the table. Unless the
	 * firewall is trusted, the rules are looked up by key first, and a
	 * rule the firewall lost is added back, so its UniqueID stays. */
	if((firewall_trust != FW_TRUST_TRUST || e->fw_partial) &&
	   fw_check_row((struct lease_entry *)e) == -2)
		return -2;
#ifdef ENABLE_LEASEFILE
	lease_file6_update(req);
#endif
	if(req->timestamp > 0)
		next_to_clean(req->timestamp);
	memmap_renew(req);
	return 0;
#else
	UNUSED(req); UNUSED(uid);

	return -42; /* not implemented */
#endif
}

int
upnp_delete_inboundpinhole(const struct lease_entry * req, unsigned short uid)
{
#ifdef FW_MAP6
	struct fw_change c;
	int ret;

	fw_change_init(&c, FW_DELETE, NULL, req);
	ret = fw_sync(&c, 1);
#ifdef ENABLE_LEASEFILE
	if (ret == 0) {
		/* a UPnP filter has its uid on its line; a PCP map has none,
		 * and its line is that of its endpoint */
		char iaddr[INET6_ADDRSTRLEN];
		if (uid != 0)
			lease_file6_remove("*", 0, 0, uid);
		else if (map_ntop(AF_INET6, &req->iaddr, iaddr, sizeof(iaddr)) != NULL)
			lease_file6_remove(iaddr, req->iport, req->proto, -1);
	}
#endif
	if (ret == 0)
		memmap_delete_filter(req);

	return ret;
#else
	UNUSED(req); UNUSED(uid);

	return -1;
#endif
}

#if 0
/*
 * Result:
 * 	 1: Found Result
 * 	-4: No result
 * 	-5: Result in another table
 * 	-6: Result in another chain
 * 	-7: Result in a chain not a rule
*/
int
upnp_check_pinhole_working(const char * uid,
                           char * eaddr,
                           char * iaddr,
                           unsigned short * eport,
                           unsigned short * iport,
                           char * protocol,
                           int * rulenum_used)
{
	/* TODO : to be implemented */
#if 0
	FILE * fd;
	time_t expire = upnp_time();
	char buf[1024], filename[] = "/var/log/kern.log", expire_time[32]="";
	int res = -4, str_len;

	str_len = strftime(expire_time, sizeof(expire_time), "%b %d %H:%M:%S", localtime(&expire));

	fd = fopen(filename, "r");
	if (fd==NULL)
	{
		syslog(LOG_ERR, "Get_rule: could not open file: %s", filename);
		return -1;
	}

	syslog(LOG_INFO, "Get_rule: Starting getting info in file %s for %s\n", filename, uid);
	buf[sizeof(buf)-1] = 0;
	while(fgets(buf, sizeof(buf)-1, fd) != NULL && res != 1)
	{
		//printf("line: %s\n", buf);
		char * r, * t, * c, * p;
		// looking for something like filter:FORWARD:rule: or filter:MINIUPNPD:rule:
		r = strstr(buf, ":rule:");
		p = strstr(buf, ":policy:");
		t = strstr(buf, "TRACE:"); // table pointeur
		t += 7;
		c = t + 7; // chain pointeur
		if(r)
		{
			printf("\t** Found %.*s\n", 24 ,t);
			char * src, * dst, * sport, * dport, * proto, * line;
			char time[15]="", src_addr[40], dst_addr[40], proto_tmp[8];
			int proto_int;
			strncpy(time, buf, sizeof(time));
			/*if(compare_time(time, expire_time)<0)
			{
				printf("\t\tNot corresponding time\n");
				continue;
			}*/

			line = r + 6;
			printf("\trule line = %d\n", atoi(line));

			src = strstr(buf, "SRC=");
			src += 4;
			snprintf(src_addr, sizeof(src_addr), "%.*s", 39, src);
#if 0
			del_char(src_addr);
			add_char(src_addr);
#endif

			dst = strstr(buf, "DST=");
			dst += 4;
			snprintf(dst_addr, sizeof(dst_addr), "%.*s", 39, dst);
#if 0
			del_char(dst_addr);
			add_char(dst_addr);
#endif

			proto = strstr(buf, "PROTO=");
			proto += 6;
			proto_int = atoi(protocol);
			if(proto_int == IPPROTO_UDP)
				strcpy(proto_tmp, "UDP");
			else if(proto_int == IPPROTO_TCP)
				strcpy(proto_tmp, "TCP");
#ifdef IPPROTO_UDPLITE
			else if(proto_int == IPPROTO_UDPLITE)
				strcpy(proto_tmp, "UDPLITE");
#endif
			else
				strcpy(proto_tmp, "UnsupportedProto");

	//		printf("\tCompare eaddr: %s // protocol: %s\n\t     to  addr: %s // protocol: %.*s\n", eaddr, proto_tmp, src_addr, strlen(proto_tmp), proto);
	//		printf("\tCompare iaddr: %s // protocol: %s\n\t     to  addr: %s // protocol: %.*s\n", iaddr, proto_tmp, dst_addr, strlen(proto_tmp), proto);
			// TODO Check time
			// Check that the paquet found in trace correspond to the one we are looking for
			if( /*(strcmp(eaddr, src_addr) == 0) &&*/ (strcmp(iaddr, dst_addr) == 0) && (strncmp(proto_tmp, proto, strlen(proto_tmp))==0))
			{
				sport = strstr(buf, "SPT=");
				sport += 4;
				dport = strstr(buf, "DPT=");
				dport += 4;
				printf("\tCompare eport: %hu\n\t     to   port: %d\n", *eport, atoi(sport));
				printf("\tCompare iport: %hu\n\t     to   port: %d\n", *iport, atoi(dport));
				if(/*eport != atoi(sport) &&*/ *iport != atoi(dport))
				{
					printf("\t\tPort not corresponding\n");
					continue;
				}
				printf("\ttable found: %.*s\n", 6, t);
				printf("\tchain found: %.*s\n", 9, c);
				// Check that the table correspond to the filter table
				if(strncmp(t, "filter", 6)==0)
				{
					// Check that the table correspond to the MINIUPNP table
					if(strncmp(c, "MINIUPNPD", 9)==0)
					{
						*rulenum_used = atoi(line);
						res = 1;
					}
					else
					{
						res = -6;
						continue;
					}
				}
				else
				{
					res = -5;
					continue;
				}
			}
			else
			{
				printf("Packet information not corresponding\n");
				continue;
			}
		}
		if(!r && p)
		{
			printf("\t** Policy case\n");
			char * src, * dst, * sport, * dport, * proto, * line;
			char time[15], src_addr[40], dst_addr[40], proto_tmp[8];
			int proto_int;
			strncpy(time, buf, sizeof(time));
			/*if(compare_time(time, expire_time)<0)
			{
				printf("\t\tNot corresponding time\n");
				continue;
			}*/

			line = p + 8;
			printf("\trule line = %d\n", atoi(line));

			src = strstr(buf, "SRC=");
			src += 4;
			snprintf(src_addr, sizeof(src_addr), "%.*s", 39, src);
#if 0
			del_char(src_addr);
			add_char(src_addr);
#endif

			dst = strstr(buf, "DST=");
			dst += 4;
			snprintf(dst_addr, sizeof(dst_addr), "%.*s", 39, dst);
#if 0
			del_char(dst_addr);
			add_char(dst_addr);
#endif

			proto = strstr(buf, "PROTO=");
			proto += 6;
			proto_int = atoi(protocol);
			if(proto_int == IPPROTO_UDP)
				strcpy(proto_tmp, "UDP");
			else if(proto_int == IPPROTO_TCP)
				strcpy(proto_tmp, "TCP");
#ifdef IPPROTO_UDPLITE
			else if(proto_int == IPPROTO_UDPLITE)
				strcpy(proto_tmp, "UDPLITE");
#endif
			else
				strcpy(proto_tmp, "UnsupportedProto");

	//		printf("\tCompare eaddr: %s // protocol: %s\n\t     to  addr: %s // protocol: %.*s\n", eaddr, proto_tmp, src_addr, strlen(proto_tmp), proto);
	//		printf("\tCompare iaddr: %s // protocol: %s\n\t     to  addr: %s // protocol: %.*s\n", iaddr, proto_tmp, dst_addr, strlen(proto_tmp), proto);
			// Check that the paquet found in trace correspond to the one we are looking for
			if( (strcmp(eaddr, src_addr) == 0) && (strcmp(iaddr, dst_addr) == 0) && (strncmp(proto_tmp, proto, 5)==0))
			{
				sport = strstr(buf, "SPT=");
				sport += 4;
				dport = strstr(buf, "DPT=");
				dport += 4;
				printf("\tCompare eport: %hu\n\t     to   port: %d\n", *eport, atoi(sport));
				printf("\tCompare iport: %hu\n\t     to   port: %d\n", *iport, atoi(dport));
				if(*eport != atoi(sport) && *iport != atoi(dport))
				{
					printf("\t\tPort not corresponding\n");
					continue;
				}
				else
				{
					printf("Find a corresponding policy trace in the chain: %.*s\n", 10, c);
					res = -7;
					continue;
				}
			}
			else
				continue;
		}
	}
	fclose(fd);
	return res;
#else
	return -42;	/* to be implemented */
#endif
}
#endif

int
upnp_delete_map6(struct lease_entry * e)
{
#ifdef FW_MAP6
	struct fw_change c;
#ifdef ENABLE_LEASEFILE
	char iaddr[INET6_ADDRSTRLEN];
#endif

	fw_change_init(&c, FW_DELETE, NULL, e);
	if(fw_sync(&c, 1) < 0)
		return -1;
#ifdef ENABLE_LEASEFILE
	/* the lines of every filter of the map */
	if(map_ntop(AF_INET6, &e->iaddr, iaddr, sizeof(iaddr)) != NULL)
		lease_file6_remove(iaddr, e->iport, e->proto, -1);
#endif
	memmap_delete(e->proto, AF_INET6, &e->iaddr, e->iport, e->eport);
	return 0;
#else
	UNUSED(e);
	return -1;
#endif
}

#endif /* ENABLE_UPNPPINHOLE */
