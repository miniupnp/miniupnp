/* $Id: upnpredirect.c,v 1.102 2025/04/12 23:14:31 nanard Exp $ */
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
#include "fwsync.h"
#include "upnpglobalvars.h"
#include "upnpevents.h"
#include "portinuse.h"
#include "upnputils.h"
#if defined(USE_NETFILTER)
#include "netfilter/iptcrdr.h"
#endif
#if defined(USE_PF)
#include "pf/obsdrdr.h"
#endif
#if defined(USE_IPF)
#include "ipf/ipfrdr.h"
#endif
#if defined(USE_IPFW)
#include "ipfw/ipfwrdr.h"
#endif
#ifdef USE_MINIUPNPDCTL
#include <stdio.h>
#include <unistd.h>
#endif
#ifdef ENABLE_LEASEFILE
#include <sys/stat.h>
#endif

/* from <inttypes.h> */
#ifndef PRIu64
#define PRIu64 "llu"
#endif

#ifdef ENABLE_LEASEFILE
static int
lease_file_add(const char * rhost,
               unsigned short eport,
               const char * iaddr,
               unsigned short iport,
               int proto,
               const char * desc,
               unsigned int timestamp)
{
	FILE * fd;

	if (lease_file == NULL) return 0;

	fd = fopen( lease_file, "a");
	if (fd==NULL) {
		syslog(LOG_ERR, "could not open lease file: %s", lease_file);
		return -1;
	}

	/* convert our time to unix time
     * if LEASEFILE_USE_REMAINING_TIME is defined, only the remaining time is stored */
	if (timestamp != 0) {
		timestamp -= upnp_time();
#ifndef LEASEFILE_USE_REMAINING_TIME
		timestamp += time(NULL);
#endif
	}

#ifdef SUPPORT_REMOTEHOST
	/* PROTO:eport:rhost:iaddr:iport:timestamp:desc */
	fprintf(fd, "%s:%hu:",
	        proto_itoa(proto), eport);
	if(rhost != NULL) {
		while(*rhost) {
			if(*rhost >= ' ' && *rhost != ':')
				fputc(*rhost, fd);
			rhost++;
		}
	}
	fprintf(fd, ":%s:%hu:%u:",
	        iaddr, iport,
	        timestamp);
#else
	/* PROTO:eport:iaddr:iport:timestamp:desc */
	fprintf(fd, "%s:%hu:%s:%hu:%u:",
	        proto_itoa(proto), eport, iaddr, iport,
	        timestamp);
#endif /* SUPPORT_REMOTEHOST */
	while(*desc) {
		/* skip non-printable characters, including CR and LF */
		if (*desc >= ' ')
			fputc(*desc, fd);
		desc++;
	}
	fputc('\n', fd);
	fclose(fd);

	return 0;
}

static int
lease_file_remove(unsigned short eport, int proto)
{
	FILE* fd, *fdt;
	int tmp;
	char buf[512];
	char str[32];
	char tmpfilename[128];
	int str_size, buf_size;


	if (lease_file == NULL) return 0;

	if (strlen( lease_file) + 7 > sizeof(tmpfilename)) {
		syslog(LOG_ERR, "Lease filename is too long");
		return -1;
	}

	snprintf( tmpfilename, sizeof(tmpfilename), "%sXXXXXX", lease_file);

	fd = fopen( lease_file, "r");
	if (fd==NULL) {
		return 0;
	}

	str_size = snprintf(str, sizeof(str), "%s:%u:", proto_itoa(proto), eport);
	if (str_size >= sizeof(str)) {
		str_size = sizeof(str) - 1;
		syslog(LOG_WARNING, "%s:%u: truncated to %s", proto_itoa(proto), eport, str);
	}

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

		if (buf_size < str_size || strncmp(str, buf, str_size)!=0) {
			fwrite(buf, buf_size, 1, fdt);
		}
	}
	fclose(fdt);
	fclose(fd);

	if (rename(tmpfilename, lease_file) < 0) {
		syslog(LOG_ERR, "could not rename temporary lease file to %s", lease_file);
		remove(tmpfilename);
	}

	return 0;

}

/* At startup the table is empty, but the rule of a lease file line may have
 * outlived the daemon. It gets a row first, with the owner its description
 * gives, so that upnp_redirect() updates the rule and adds no second one.
 * One firewall read per line, at startup only. */
static void
reload_adopt_rule(const struct lease_entry * line)
{
	char iaddr_s[INET6_ADDRSTRLEN];
	char desc[64];
	char rhost[INET6_ADDRSTRLEN];
	unsigned short iport;
	int family;
	struct lease_entry * e;

	rhost[0] = '\0';
	desc[0] = '\0';
	if(get_redirect_rule(ext_if_name, line->eport, line->proto, iaddr_s, sizeof(iaddr_s),
	                     &iport, desc, sizeof(desc), rhost, sizeof(rhost),
	                     NULL, 0, 0) != 0)
		return;
	e = lease_table_new(1);
	if(e == NULL)
		return;
	if(map_pton(iaddr_s, &family, &e->iaddr) < 0 || family != AF_INET ||
	   map_filter_set(&e->filters[0], rhost, 0) < 0) {
		lease_table_free(e);
		return;
	}
	e->nfilters = e->filters[0].prefix != 0 ? 1 : 0;
	e->family = AF_INET;
	e->proto = line->proto;
	e->iport = iport;
	e->eaddr = line->eaddr;
	e->eport = line->eport;
	/* the lease of the line, so the rule expires also if the renewal
	 * below fails */
	e->timestamp = line->timestamp;
	lease_entry_from_desc(e, desc);
	memmap_add(e);	/* the table takes e, with a copy of its label */
}

/* reload_from_lease_file()
 * read lease_file and add the rules contained
 */
int reload_from_lease_file(void)
{
	FILE * fd;
	char * p;
	unsigned short eport, iport;
	char * proto;
	char * iaddr;
	char * desc;
	char * rhost = NULL;
	unsigned int leaseduration;
	unsigned int timestamp;
	time_t current_time;
#ifndef LEASEFILE_USE_REMAINING_TIME
	time_t current_unix_time;
#endif
	char line[320];
	int r, family;
	struct lease_entry * req;

	if(!lease_file) return -1;
	fd = fopen( lease_file, "r");
	if (fd==NULL) {
		syslog(LOG_ERR, "could not open lease file: %s", lease_file);
		return -1;
	}
	if(unlink(lease_file) < 0) {
		syslog(LOG_WARNING, "could not unlink file %s : %m", lease_file);
	}

	current_time = upnp_time();
#ifndef LEASEFILE_USE_REMAINING_TIME
	current_unix_time = time(NULL);
#endif
	while(fgets(line, sizeof(line), fd)) {
		syslog(LOG_DEBUG, "parsing lease file line '%s'", line);
		proto = line;
		p = strchr(line, ':');
		if(!p) {
			syslog(LOG_ERR, "unrecognized data in lease file");
			continue;
		}
		*(p++) = '\0';
		eport = (unsigned short)atoi(p);
#ifdef SUPPORT_REMOTEHOST
		p = strchr(p, ':');
		if(!p) {
			syslog(LOG_ERR, "unrecognized data in lease file");
			continue;
		}
		rhost = ++p;
#endif /* SUPPORT_REMOTEHOST */
		iaddr = strchr(p, ':');
		if(!iaddr) {
			syslog(LOG_ERR, "unrecognized data in lease file");
			continue;
		}
		*(iaddr++) = '\0';
		p = strchr(iaddr, ':');
		if(!p) {
			syslog(LOG_ERR, "unrecognized data in lease file");
			continue;
		}
		*(p++) = '\0';
		iport = (unsigned short)atoi(p);
		p = strchr(p, ':');
		if(!p) {
			syslog(LOG_ERR, "unrecognized data in lease file");
			continue;
		}
		*(p++) = '\0';
		timestamp = (unsigned int)strtoul(p, NULL, 10);
		desc = strchr(p, ':');
		if(!desc) {
			syslog(LOG_ERR, "unrecognized data in lease file");
			continue;
		}
		*(desc++) = '\0';
		/* trim description */
		while(isspace(*desc))
			desc++;
		p = desc;
		while(*(p+1))
			p++;
		while(isspace(*p) && (p > desc))
			*(p--) = '\0';

		if(timestamp > 0) {
#ifdef LEASEFILE_USE_REMAINING_TIME
			leaseduration = timestamp;
			timestamp += current_time;	/* convert to our time */
#else
			if(timestamp <= (unsigned int)current_unix_time) {
				syslog(LOG_NOTICE, "already expired lease in lease file (%hu=>%s:%hu %s)",
				       eport, iaddr, iport, proto);
				continue;
			} else {
				leaseduration = timestamp - current_unix_time;
				timestamp = leaseduration + current_time; /* convert to our time */
			}
#endif
		} else {
			leaseduration = 0;	/* default value */
		}
		req = lease_table_new(1);
		if(req == NULL)
			continue;
		lease_entry_set_kind(req, MAP_KIND_UPNP, NULL);
		if(map_pton(iaddr, &family, &req->iaddr) < 0 || family != AF_INET ||
		   map_filter_set(&req->filters[0], rhost, 0) < 0) {
			syslog(LOG_WARNING, "ignoring lease file line with an invalid address (%hu=>%s:%hu %s)",
			       eport, iaddr, iport, proto);
			lease_table_free(req);
			continue;
		}
		req->family = AF_INET;
		req->proto = proto_atoi(proto);
		req->iport = iport;
		req->eport = eport;
		/* any remote host: no filter */
		req->nfilters = req->filters[0].prefix != 0 ? 1 : 0;
		lease_entry_from_desc(req, desc);
		req->timestamp = leaseduration > 0 ? timestamp : 0;
		reload_adopt_rule(req);
		r = upnp_redirect(req);
		if(r != 0)
			lease_table_free(req);	/* on success the lease table took it */
		if(r == -1) {
			syslog(LOG_ERR, "Failed to redirect %hu -> %s:%hu protocol %s",
			       eport, iaddr, iport, proto);
		} else if(r == -2) {
			/* Add the redirection again to the lease file */
			lease_file_add(rhost, eport, iaddr, iport, proto_atoi(proto),
			               desc, timestamp);
		}
	}
	fclose(fd);

	return 0;
}

/* the lease file line of the IPv4 port mapping e */
static int
lease_file_add_row(const struct lease_entry * e)
{
	char iaddr[INET_ADDRSTRLEN];
	char desc[64];
	char rhost[INET6_ADDRSTRLEN];

	map_ntop(AF_INET, &e->iaddr, iaddr, sizeof(iaddr));
	return lease_file_add(map_rhost(e, rhost, sizeof(rhost)), e->eport, iaddr,
	                      e->iport, e->proto, map_rule_desc(e, desc, sizeof(desc)),
	                      e->timestamp);
}

#ifdef LEASEFILE_USE_REMAINING_TIME
void lease_file_rewrite(void)
{
	const struct lease_entry * e;

	if (lease_file == NULL) return;
	remove(lease_file);
	for(e = lease_table_next_port(NULL); e != NULL; e = lease_table_next_port(e)) {
		if(lease_file_add_row(e) < 0)
			break;
	}
}
#endif
#endif

/* the next expiry, ts if it is sooner */
static void
next_to_clean(unsigned int ts)
{
	if(nextruletoclean_timestamp == 0 || ts < nextruletoclean_timestamp)
		nextruletoclean_timestamp = ts;
}

/* An add which failed left a part of the rules of e in the firewall: the
 * table keeps a row of them, which expires at once, so the expiry pass
 * deletes them again. */
static void
keep_partial_row(const struct lease_entry * e)
{
	struct lease_entry * k = lease_table_copy(e);

	if(k == NULL) {
		syslog(LOG_ERR, "port %hu %s: no row for the rules which stay",
		       e->eport, proto_itoa(e->proto));
		return;
	}
	k->fw_partial = 1;
	k->timestamp = (unsigned int)upnp_time();
	next_to_clean(k->timestamp);
	memmap_add(k);	/* the table takes k */
}

/* upnp_redirect()
 * calls OS/fw dependent implementation of the redirection.
 * protocol should be the string "TCP" or "UDP"
 * returns: 0 on success
 *          -1 failed to redirect
 *          -2 already redirected
 *          -3 permission check failed
 *          -4 already redirected (other mechanism)
 */
int
upnp_redirect(struct lease_entry * req)
{
	int r;
	char desc_buf[64];
	const char * desc = map_rule_desc(req, desc_buf, sizeof(desc_buf));
	char iaddr[INET_ADDRSTRLEN];
	char rhost_buf[INET6_ADDRSTRLEN];
	const char * rhost;
	char iaddr_old[INET_ADDRSTRLEN];
	char rhost_old_buf[INET6_ADDRSTRLEN];
	const char * rhost_old;
	unsigned short iport_old;
	struct lease_entry * old;
	struct fw_change c;
	const unsigned short eport = req->eport;
	const unsigned short iport = req->iport;
	const int proto = req->proto;
	const char * protocol = proto_itoa(proto);

	map_ntop(AF_INET, &req->iaddr, iaddr, sizeof(iaddr));
	rhost = map_rhost(req, rhost_buf, sizeof(rhost_buf));

	if(!check_upnp_rule_against_permissions(upnppermlist, num_upnpperm, req)) {
		syslog(LOG_INFO, "redirection permission check failed for "
		                 "%hu->%s:%hu %s %s", eport, iaddr, iport, protocol, desc);
		return -3;
	}

	/* IGDv1 (WANIPConnection:1 Service Template Version 1.01 / Nov 12, 2001)
	 * - 2.2.20.PortMappingDescription :
	 *  Overwriting Previous / Existing Port Mappings:
	 * If the RemoteHost, ExternalPort, PortMappingProtocol and InternalClient
	 * are exactly the same as an existing mapping, the existing mapping values
	 * for InternalPort, PortMappingDescription, PortMappingEnabled and
	 * PortMappingLeaseDuration are overwritten.
	 *  Rejecting a New Port Mapping:
	 * In cases where the RemoteHost, ExternalPort and PortMappingProtocol
	 * are the same as an existing mapping, but the InternalClient is
	 * different, the action is rejected with an appropriate error.
	 *  Add or Reject New Port Mapping behavior based on vendor implementation:
	 * In cases where the ExternalPort, PortMappingProtocol and InternalClient
	 * are the same, but RemoteHost is different, the vendor can choose to
	 * support both mappings simultaneously, or reject the second mapping
	 * with an appropriate error.
	 *
	 * - 2.4.16.AddPortMapping
	 * This action creates a new port mapping or overwrites an existing
	 * mapping with the same internal client. If the ExternalPort and
	 * PortMappingProtocol pair is already mapped to another internal client,
	 * an error is returned.
	 *
	 * IGDv2 (WANIPConnection:2 Service Standardized DCP (SDCP) Sep 10, 2010)
	 * Protocol ExternalPort RemoteHost InternalClient Result
	 *     =         =           ≠           ≠         Failure
	 *     =         =           ≠           =         Failure or success
	 *                                                 (vendor specific)
	 *     =         =           =           ≠         Failure
	 *     =         =           =           =         Success (overwrite)
	 */
	old = upnp_check_map(memmap_find_map(proto, req->family, &req->eaddr, eport));
	if(old != NULL) {
		map_ntop(AF_INET, &old->iaddr, iaddr_old, sizeof(iaddr_old));
		iport_old = old->iport;
		rhost_old = map_rhost(old, rhost_old_buf, sizeof(rhost_old_buf));
		if(strcmp(iaddr, iaddr_old)==0 &&
		   ((rhost == NULL && rhost_old == NULL) ||
		    (rhost && rhost_old && (strcmp(rhost, rhost_old) == 0)))) {
			syslog(LOG_INFO, "updating existing port mapping %hu %s (rhost '%s') => %s:%hu",
				eport, protocol, rhost_old ? rhost_old : "", iaddr_old, iport_old);
			if(iport == iport_old)
				return upnp_renew_map(req, old);
			fw_change_init(&c, FW_UPDATE, req, old);
			r = fw_sync(&c, 1);
#ifdef ENABLE_LEASEFILE
			if(r == 0) {
				lease_file_remove(eport, proto);
				lease_file_add_row(req);
			}
#endif /* ENABLE_LEASEFILE */
			if(r == 0)
				memmap_update(req, iport_old);	/* the table takes req */
			return r;
		} else {
			syslog(LOG_INFO, "port %hu %s (rhost '%s') already redirected to %s:%hu",
				eport, protocol, rhost_old ? rhost_old : "", iaddr_old, iport_old);
			return -2;
		}
#ifdef CHECK_PORTINUSE
	} else if (port_in_use(ext_if_name, eport, proto, iaddr, iport) > 0) {
		syslog(LOG_INFO, "port %hu protocol %s already in use",
		       eport, protocol);
		return -4;
#endif /* CHECK_PORTINUSE */
	} else {
		syslog(LOG_INFO, "redirecting port %hu to %s:%hu protocol %s for: %s",
			eport, iaddr, iport, protocol, desc);
		return upnp_redirect_internal(req);
	}
}

int
upnp_redirect_internal(struct lease_entry * req)
{
	struct fw_change c;

	if(disable_port_forwarding)
		return -1;
	fw_change_init(&c, FW_ADD, req, NULL);
	c.fresh = 1;	/* the callers found no row on the port */
	if(fw_sync(&c, 1) < 0) {
		if(c.applied != FW_NOT_APPLIED)
			keep_partial_row(req);
		return -1;
	}
#ifdef ENABLE_LEASEFILE
	lease_file_add_row(req);
#endif
	if(req->timestamp > 0)
		next_to_clean(req->timestamp);
#ifdef ENABLE_EVENTS
	/* the number of port mappings changed, we must
	 * inform the subscribers */
	upnp_event_var_change_notify(EWanIPC);
#endif
	memmap_add(req);	/* the table takes req */
	return 0;
}

int
upnp_renew_map(struct lease_entry * req, struct lease_entry * old)
{
	const unsigned short iport_old = old->iport;

	if(disable_port_forwarding) {
		/* no port forwarding now: the mapping goes and the renewal
		 * fails, as a new one would */
		syslog(LOG_INFO, "port forwarding is off, removing port mapping %hu %s",
		       old->eport, proto_itoa(old->proto));
		upnp_delete_map(old);
		return -1;
	}
#ifdef ENABLE_LEASEFILE
	lease_file_remove(req->eport, req->proto);
	lease_file_add_row(req);
#endif
	if(req->timestamp > 0)
		next_to_clean(req->timestamp);
	memmap_update(req, iport_old);	/* the table takes req; old goes */
	return 0;
}



/* The values UPnP gives of the mapping of row e. desc is the description
 * of its rule, as the firewall gave it before (map_rule_desc()). */
static void
row_infos(const struct lease_entry * e, unsigned short * iport,
          char * iaddr, int iaddrlen, char * desc, int desclen,
          char * rhost, int rhostlen, unsigned int * leaseduration)
{
	char desc_buf[64];
	char rhost_buf[INET6_ADDRSTRLEN];
	const char * r;
	unsigned int now;

	*iport = e->iport;
	if(map_ntop(e->family, &e->iaddr, iaddr, (size_t)iaddrlen) == NULL && iaddrlen > 0)
		iaddr[0] = '\0';
	if(desc && desclen > 0)
		snprintf(desc, (size_t)desclen, "%s", map_rule_desc(e, desc_buf, sizeof(desc_buf)));
	if(rhost && rhostlen > 0) {
		r = map_rhost(e, rhost_buf, sizeof(rhost_buf));
		snprintf(rhost, (size_t)rhostlen, "%s", r ? r : "");
	}
	now = (unsigned int)upnp_time();
	*leaseduration = e->timestamp > now ? e->timestamp - now : 0;
}

int
upnp_get_redirection_infos(const struct in6_addr * eaddr,
                           unsigned short eport, const char * protocol,
                           unsigned short * iport,
                           char * iaddr, int iaddrlen,
                           char * desc, int desclen,
                           char * rhost, int rhostlen,
                           unsigned int * leaseduration)
{
	const struct lease_entry * e;

	e = memmap_find_map(proto_atoi(protocol), AF_INET, eaddr, eport);
	if(e == NULL) {
		if(desc && (desclen > 0))
			desc[0] = '\0';
		if(rhost && (rhostlen > 0))
			rhost[0] = '\0';
		*leaseduration = 0;
		return -1;
	}
	row_infos(e, iport, iaddr, iaddrlen, desc, desclen, rhost, rhostlen,
	          leaseduration);
	return 0;
}

int
upnp_get_redirection_infos_by_index(int index,
                                    unsigned short * eport, char * protocol,
                                    unsigned short * iport,
                                    char * iaddr, int iaddrlen,
                                    char * desc, int desclen,
                                    char * rhost, int rhostlen,
                                    unsigned int * leaseduration)
{
	const struct lease_entry * e;

	if(index < 0 || (e = lease_table_port_at((unsigned int)index)) == NULL)
		return -1;
	*eport = e->eport;
	/* protocol holds 8 bytes */
	snprintf(protocol, 8, "%s", proto_itoa(e->proto));
	row_infos(e, iport, iaddr, iaddrlen, desc, desclen, rhost, rhostlen,
	          leaseduration);
	return 0;
}

int
upnp_get_redirection_infos_by_ituple(unsigned short iport,
                                     const char * iaddr, int proto,
                                     unsigned short * eport,
                                     char * desc, int desclen,
                                     char * rhost, int rhostlen,
                                     unsigned int * leaseduration)
{
	/* that is a default implementation, iterating all rules */
	int index;

	for(index = 0; ; index++) {
		unsigned short other_iport = 0;
		int other_proto = 0;
		char other_iaddr[16] = "";
		unsigned int timestamp;

		if(get_redirect_rule_by_index(index, 0/*ifname*/, eport,
		                              other_iaddr, sizeof(other_iaddr),
		                              &other_iport, &other_proto,
		                              desc, desclen,
		                              rhost, rhostlen, &timestamp,
		                              0, 0) < 0)
			break;
		if(other_proto == proto && other_iport == iport &&
		   strcmp(other_iaddr, iaddr) == 0) {
			/* found it ! */
			if(leaseduration) {
				time_t current_time = upnp_time();
				*leaseduration = (timestamp > (unsigned int)current_time)
				                 ? (timestamp - current_time)
				                 : 0;
			}
			return 0;
		}
	}
	/* not found */
	if(index > 0) {
		/* clean the mess */
		*eport = 0;
		desc[0] = '\0';
		rhost[0] = '\0';
	}
	return -1;
}

int
_upnp_delete_redir(unsigned short eport, int proto)
{
	int r;

#if defined(__linux__)
	r = delete_redirect_and_filter_rules(eport, proto);
#elif defined(USE_PF)
	r = delete_redirect_and_filter_rules(ext_if_name, eport, proto);
#else
	r = delete_redirect_rule(ext_if_name, eport, proto);
	delete_filter_rule(ext_if_name, eport, proto);
#endif
#ifdef ENABLE_LEASEFILE
	lease_file_remove(eport, proto);
#endif

#ifdef ENABLE_EVENTS
	upnp_event_var_change_notify(EWanIPC);
#endif
	return r;
}

struct lease_entry *
upnp_check_map(struct lease_entry * e)
{
	struct fw_change c;
	int r;

	if(e == NULL || firewall_trust == FW_TRUST_TRUST)
		return e;
	/* a failed read (-1) is no missing rule (-2): the row of a rule which
	 * may be there stays */
	r = fw_map_rule(e->eport, e->proto, NULL, NULL);
	if(r != -2)
		return e;
	/* The rule went without the daemon. The row says what it was: add it
	 * back in place, so the mapping keeps its row, and the UPnP index of
	 * the mappings after it does not move. */
	fw_change_init(&c, FW_ADD, e, NULL);
	c.fresh = 1;
	if(fw_sync(&c, 1) == 0) {
		syslog(LOG_NOTICE, "port mapping %hu %s lost its rule, added it back",
		       e->eport, proto_itoa(e->proto));
		e->fw_partial = 0;
		return e;
	}
	if(c.applied != FW_NOT_APPLIED) {
		/* a part of the rules is back: the row stays with them */
		e->fw_partial = 1;
		return e;
	}
	syslog(LOG_NOTICE, "port mapping %hu %s lost its rule, which could not be added "
	       "back: its row goes", e->eport, proto_itoa(e->proto));
#ifdef ENABLE_LEASEFILE
	lease_file_remove(e->eport, e->proto);
#endif
	memmap_delete(e->proto, e->family, &e->iaddr, e->iport, e->eport);
	return NULL;
}

int
upnp_delete_map(struct lease_entry * e)
{
	struct fw_change c;
	int r;

	fw_change_init(&c, FW_DELETE, NULL, e);
	r = fw_sync(&c, 1);
	if(r < 0)
		return r;
#ifdef ENABLE_LEASEFILE
	lease_file_remove(e->eport, e->proto);
#endif
#ifdef ENABLE_EVENTS
	upnp_event_var_change_notify(EWanIPC);
#endif
	memmap_delete(e->proto, e->family, &e->iaddr, e->iport, e->eport);
	return 0;
}

int
upnp_delete_port(unsigned short eport, int proto)
{
	struct lease_entry * e;

	for(e = lease_table_next_port(NULL); e != NULL; e = lease_table_next_port(e))
		if(e->eport == eport && e->proto == proto)
			return upnp_delete_map(e);
	return -1;
}

/* called from natpmp.c and pcpserver.c */
int
upnp_eport_used_by_other(const struct lease_entry * req)
{
	char iaddr_old[INET6_ADDRSTRLEN];
	const struct lease_entry * e;
	const struct outgoing_entry * b;

	/* the lease table, then the PEER bindings: only memory */
	e = memmap_eport_used_by_other(req->family, &req->eaddr, req->eport, &req->iaddr);
	if(e != NULL) {
		syslog(LOG_INFO, "external port %hu is used by %s (%s)", req->eport,
		       map_ntop(e->family, &e->iaddr, iaddr_old, sizeof(iaddr_old)) ? iaddr_old : "?",
		       proto_itoa(e->proto));
		return 1;
	}
	b = memmap_peer_port_used_by_other(req->family, &req->eaddr, req->eport, &req->iaddr);
	if(b != NULL) {
		syslog(LOG_INFO, "external port %hu is used by a PEER of %s (%s)", req->eport,
		       map_ntop(b->family, &b->iaddr, iaddr_old, sizeof(iaddr_old)) ? iaddr_old : "?",
		       proto_itoa(b->proto));
		return 1;
	}
	return 0;
}

int
upnp_delete_redirection(const struct lease_entry * req)
{
	struct lease_entry * e = memmap_find_map(req->proto, req->family, &req->eaddr,
	                                         req->eport);

	if(e == NULL)
		return -1;
	syslog(LOG_INFO, "removing redirect rule port %hu %s", req->eport,
	       proto_itoa(req->proto));
	return upnp_delete_map(e);
}

/* upnp_get_portmapping_number_of_entries() */
int
upnp_get_portmapping_number_of_entries(void)
{
	return (int)lease_table_port_count();
}

/* seconds before an expired mapping whose rules stayed is deleted again */
#define EXPIRY_RETRY	60

#ifdef PCP_PEER
/* Delete the PEER rules of the keys of expired peers: one transaction. */
static void
expire_peer_rules(struct outgoing_rule_key * keys, int n)
{
	int i;

	if(outgoing_rule_delete(keys, n) < 0) {
		syslog(LOG_WARNING, "%d expired PEER mappings, their rules were not deleted", n);
		return;
	}
	for(i = 0; i < n; i++)
		if(keys[i].result != 0)
			syslog(LOG_INFO, "expired PEER mapping %hu %s had no rule",
			       keys[i].eport, proto_itoa(keys[i].proto));
}
#endif

void
upnp_expire_mappings(void)
{
	struct lease_entry * e, * next;
	unsigned int now = (unsigned int)upnp_time();
#ifdef PCP_PEER
	struct outgoing_rule_key keys[OUTGOING_RULE_DELETE_MAX], * k;
	struct outgoing_entry * b;
	int i, n = 0;
#endif

	nextruletoclean_timestamp = 0;
	for(e = lease_table_next_port(NULL); e != NULL; e = next) {
		next = lease_table_next_port(e);
		if(e->timestamp == 0)
			continue;
		if(e->timestamp > now) {
			next_to_clean(e->timestamp);
			continue;
		}
		if(e->retry > now) {
			next_to_clean(e->retry);
			continue;
		}
		syslog(LOG_NOTICE, "remove port mapping %hu %s because it has expired",
		       e->eport, proto_itoa(e->proto));
		/* A rule the firewall lost deletes fine (fw_sync()). A delete
		 * which fails keeps the row, so the rule is not left without
		 * one: the next try is a minute later. */
		if(upnp_delete_map(e) < 0) {
			e->retry = now + EXPIRY_RETRY;
			next_to_clean(e->retry);
			syslog(LOG_WARNING, "port mapping %hu %s expired, its rules were not deleted, "
			       "next try in %d s", e->eport, proto_itoa(e->proto), EXPIRY_RETRY);
		}
	}
#ifdef PCP_PEER
	/* the PEER peers: the rule of each peer, never the port mapping on the
	 * same external port, nor the other peers of its binding. */
	for(b = outgoing_table_next(NULL); b != NULL; b = outgoing_table_next(b)) {
		for(i = 0; i < b->npeers; i++) {
			if(b->peers[i].timestamp == 0)
				continue;
			if(b->peers[i].timestamp > now) {
				next_to_clean(b->peers[i].timestamp);
				continue;
			}
			syslog(LOG_NOTICE, "remove PEER mapping %hu %s because it has expired",
			       b->eport, proto_itoa(b->proto));
			if(!IN6_IS_ADDR_V4MAPPED(&b->iaddr) ||
			   !IN6_IS_ADDR_V4MAPPED(&b->peers[i].raddr))
				continue;	/* no IPv6 PEER rules */
			k = &keys[n++];
			memcpy(&k->iaddr, &b->iaddr.s6_addr[12], sizeof(k->iaddr));
			memcpy(&k->raddr, &b->peers[i].raddr.s6_addr[12], sizeof(k->raddr));
			k->iport = b->iport;
			k->rport = b->peers[i].rport;
			k->eport = b->eport;
			k->proto = b->proto;
			if(n == OUTGOING_RULE_DELETE_MAX) {
				expire_peer_rules(keys, n);
				n = 0;
			}
		}
	}
	if(n > 0)
		expire_peer_rules(keys, n);
	/* the peers go also if their rules do not, as the port mappings do */
	memmap_outgoing_expired(now);
#endif
}

/* functions used to remove unused rules
 * As a side effect, delete expired rules (based on LeaseDuration) */
struct rule_state *
get_upnp_rules_state_list(int max_rules_number_target)
{
	const struct lease_entry * e;
	struct rule_state * tmp;
	struct rule_state * list = 0;
	unsigned short iport;
	unsigned int timestamp;

	upnp_expire_mappings();
	if(lease_table_port_count() <= (unsigned int)max_rules_number_target)
		return NULL;
	/* the counters of the rules: only the firewall has them. Only UPnP
	 * mappings are removed when unused: those of PCP and NAT-PMP last the
	 * lifetime their client asked for. */
	for(e = lease_table_next_port(NULL); e != NULL; e = lease_table_next_port(e)) {
		if(e->kind != MAP_KIND_UPNP)
			continue;
		tmp = malloc(sizeof(struct rule_state));
		if(!tmp)
			break;
		if(get_redirect_rule(ext_if_name, e->eport, e->proto, 0, 0, &iport,
		                     0, 0, 0, 0, &timestamp,
		                     &tmp->packets, &tmp->bytes) < 0) {
			free(tmp);
			continue;
		}
		tmp->eport = e->eport;
		tmp->proto = e->proto;
		tmp->to_remove = 0;
		tmp->next = list;
		list = tmp;
	}
	return list;
}

void
remove_unused_rules(struct rule_state * list)
{
	char ifname[IFNAMSIZ];
	unsigned short iport;
	struct rule_state * tmp;
	u_int64_t packets;
	u_int64_t bytes;
	unsigned int timestamp;
	int n = 0;

	while(list)
	{
		/* remove the rule if no traffic has used it */
		if(get_redirect_rule(ifname, list->eport, list->proto,
	                         0, 0, &iport, 0, 0, 0, 0, &timestamp,
		                     &packets, &bytes) >= 0)
		{
			if(packets == list->packets && bytes == list->bytes)
			{
				syslog(LOG_DEBUG, "removing unused mapping %hu %s : still "
				       "%" PRIu64 "packets %" PRIu64 "bytes",
				       list->eport, proto_itoa(list->proto),
				       packets, bytes);
				upnp_delete_port(list->eport, list->proto);
				n++;
			}
		}
		tmp = list;
		list = tmp->next;
		free(tmp);
	}
	if(n>0)
		syslog(LOG_NOTICE, "removed %d unused rules", n);
}

/* upnp_get_portmappings_in_range()
 * return a list of all "external" ports for which a port
 * mapping exists */
unsigned short *
upnp_get_portmappings_in_range(unsigned short startport,
                               unsigned short endport,
                               const char * protocol,
                               unsigned int * number)
{
	const struct lease_entry * e;
	unsigned short * list = NULL, * tmp;
	unsigned int alloc = 0;
	int proto = proto_atoi(protocol);

	if(!number)
		return NULL;
	*number = 0;
	for(e = lease_table_next_port(NULL); e != NULL; e = lease_table_next_port(e)) {
		if(e->proto != proto || e->eport < startport || e->eport > endport)
			continue;
		if(*number >= alloc) {
			alloc = alloc ? 2 * alloc : 16;
			tmp = realloc(list, alloc * sizeof(*list));
			if(tmp == NULL) {
				syslog(LOG_ERR, "upnp_get_portmappings_in_range(): realloc failed");
				break;
			}
			list = tmp;
		}
		list[(*number)++] = e->eport;
	}
	return list;
}

/* stuff for miniupnpdctl */
#ifdef USE_MINIUPNPDCTL
void
write_ruleset_details(int s)
{
	int proto = 0;
	unsigned short eport, iport;
	char desc[64];
	char iaddr[32];
	char rhost[32];
	unsigned int timestamp;
	u_int64_t packets;
	u_int64_t bytes;
	int i = 0;
	char buffer[256];
	int n;

	write(s, "Ruleset :\n", 10);
	while(get_redirect_rule_by_index(i, 0/*ifname*/, &eport, iaddr, sizeof(iaddr),
	                                 &iport, &proto, desc, sizeof(desc),
	                                 rhost, sizeof(rhost),
	                                 &timestamp,
	                                 &packets, &bytes) >= 0)
	{
		n = snprintf(buffer, sizeof(buffer),
		             "%2d %s %s:%hu->%s:%hu "
		             "'%s' %u %" PRIu64 " %" PRIu64 "\n",
		             /*"'%s' %llu %llu\n",*/
		             i, proto_itoa(proto), rhost,
		             eport, iaddr, iport, desc, timestamp, packets, bytes);
		write(s, buffer, n);
		i++;
	}
}
#endif
