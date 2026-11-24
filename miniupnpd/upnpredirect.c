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
#ifdef ENABLE_UPNPPINHOLE
#include "upnppinhole.h"
#endif
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

/* from <inttypes.h> */
#ifndef PRIu64
#define PRIu64 "llu"
#endif

/* the next expiry, ts if it is sooner */
void
next_to_clean(unsigned int ts)
{
	if(nextruletoclean_timestamp == 0 || ts < nextruletoclean_timestamp)
		nextruletoclean_timestamp = ts;
}

/* An add which failed left a part of the rules of e in the firewall: the
 * table keeps a row of them, which expires at once, so the expiry pass
 * deletes them again. */
void
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
			/* the same client: only the protocol which made the
			 * mapping changes it */
			if(old->kind != req->kind) {
				syslog(LOG_INFO, "port %hu %s is a %s mapping, which %s may not change",
				       eport, protocol, map_kind_name(old->kind), map_kind_name(req->kind));
				return -4;
			}
			syslog(LOG_INFO, "updating existing port mapping %hu %s (rhost '%s') => %s:%hu",
				eport, protocol, rhost_old ? rhost_old : "", iaddr_old, iport_old);
			if(iport == iport_old)
				return upnp_renew_map(req, old);
			fw_change_init(&c, FW_UPDATE, req, old);
			r = fw_sync(&c, 1);
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
	/* the callers found no row on the port, and since
	 * drop_rules_without_row() no rule is without a row */
	c.fresh = 1;
	if(fw_sync(&c, 1) < 0) {
		if(c.applied != FW_NOT_APPLIED)
			keep_partial_row(req);
		return -1;
	}
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

	/* a part of its rules is missing: no renewal in the table, the row
	 * expires and the client maps anew */
	if(old->fw_partial)
		return -1;
	if(disable_port_forwarding) {
		/* no port forwarding now: the mapping goes and the renewal
		 * fails, as a new one would */
		syslog(LOG_INFO, "port forwarding is off, removing port mapping %hu %s",
		       old->eport, proto_itoa(old->proto));
		upnp_delete_map(old);
		return -1;
	}
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

struct lease_entry *
upnp_check_map(struct lease_entry * e)
{
	/* a row of a part of its rules is checked even in a trusted firewall:
	 * the daemon knows they are not all there */
	if(e == NULL || (firewall_trust == FW_TRUST_TRUST && !e->fw_partial))
		return e;
	if(fw_check_row(e) != -2)
		return e;	/* there, sent again, or not known */
	if(e->fw_partial) {
		/* a part of the rules stays: so does the row, which expires
		 * at once, so the expiry deletes them */
		e->timestamp = (unsigned int)upnp_time();
		next_to_clean(e->timestamp);
		return e;
	}
	syslog(LOG_NOTICE, "port mapping %hu %s lost its rule, which could not be added "
	       "back: its row goes", e->eport, proto_itoa(e->proto));
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
/* at most this many mappings go in one pass, of any kind, so a large expiry
 * does not hold up the requests: the next pass comes at once */
#define EXPIRE_MAX_PER_PASS	64

/* 1 if the row is due: its expiry, or the retry after a failed delete, has
 * come. Else 0, and its time is the next expiry if it is sooner. */
static int
row_due(const struct lease_entry * e, unsigned int now)
{
	unsigned int ts;

	if(e->timestamp == 0)
		return 0;
	ts = e->retry > e->timestamp ? e->retry : e->timestamp;
	if(ts > now) {
		next_to_clean(ts);
		return 0;
	}
	return 1;
}

/* A delete of an expired row failed: the row keeps its rules, and the next
 * try is a minute later. A rule the firewall lost deletes fine
 * (fw_sync()), so such a row does not come back on every pass. */
static void
retry_later(struct lease_entry * e, unsigned int now, const char * what)
{
	e->retry = now + EXPIRY_RETRY;
	next_to_clean(e->retry);
	syslog(LOG_WARNING, "%s %hu %s expired, its rules were not deleted, next try in %d s",
	       what, e->family == AF_INET ? e->eport : e->iport,
	       proto_itoa(e->proto), EXPIRY_RETRY);
}

#ifdef ENABLE_UPNPPINHOLE
/* the IPv6 maps due, which the walk of the table collects: the rows can
 * not go while it walks */
struct map6_due {
	unsigned int now;
	int left;
	int n;
	struct lease_entry * due[EXPIRE_MAX_PER_PASS];
};

static void
collect_map6(struct lease_entry * e, void * arg)
{
	struct map6_due * d = arg;

	if(e->family != AF_INET6 || !row_due(e, d->now))
		return;
	if(d->n >= d->left) {
		next_to_clean(d->now);	/* the next pass takes it */
		return;
	}
	d->due[d->n++] = e;
}
#endif


void
expire_mappings(void)
{
	struct lease_entry * e, * next;
	unsigned int now = (unsigned int)upnp_time();
	int left = EXPIRE_MAX_PER_PASS;
#ifdef ENABLE_UPNPPINHOLE
	struct map6_due d;
	int i;
#endif
#ifdef PCP_PEER
	struct outgoing_entry * b, * b_next;
	struct fw_out_change c;
	int p, last;
#endif

	nextruletoclean_timestamp = 0;
	/* the IPv4 port mappings: the port list */
	for(e = lease_table_next_port(NULL); e != NULL; e = next) {
		next = lease_table_next_port(e);
		if(!row_due(e, now))
			continue;
		if(left == 0) {
			next_to_clean(now);
			break;
		}
		left--;
		syslog(LOG_NOTICE, "remove port mapping %hu %s because it has expired",
		       e->eport, proto_itoa(e->proto));
		if(upnp_delete_map(e) < 0)
			retry_later(e, now, "port mapping");
	}
#ifdef ENABLE_UPNPPINHOLE
	/* the IPv6 maps: the rows of the table */
	memset(&d, 0, sizeof(d));
	d.now = now;
	d.left = left;
	lease_table_foreach(collect_map6, &d);
	for(i = 0; i < d.n; i++) {
		e = d.due[i];
		left--;
		syslog(LOG_NOTICE, "remove map6 port %hu %s because it has expired",
		       e->iport, proto_itoa(e->proto));
		if(upnp_delete_map6(e) < 0)
			retry_later(e, now, "map6 port");
	}
#endif
#ifdef PCP_PEER
	/* the PEER peers: the outgoing table. A peer goes once its rule is
	 * deleted. */
	for(b = outgoing_table_next(NULL); b != NULL; b = b_next) {
		b_next = outgoing_table_next(b);
		/* backwards: a peer which goes moves only those after it */
		for(p = b->npeers - 1; p >= 0; p--) {
			struct outgoing_peer * q = &b->peers[p];
			unsigned int ts;
			if(q->timestamp == 0)
				continue;
			ts = q->retry > q->timestamp ? q->retry : q->timestamp;
			if(ts > now) {
				next_to_clean(ts);
				continue;
			}
			if(left == 0) {
				next_to_clean(now);
				continue;
			}
			left--;
			syslog(LOG_NOTICE, "remove PEER mapping %hu %s because it has expired",
			       b->eport, proto_itoa(b->proto));
			fw_out_change_init(&c, FW_OUT_DELETE, b, p);
			if(fw_sync_out(&c, 1) < 0) {
				/* the rule stays: so does the peer */
				q->retry = now + EXPIRY_RETRY;
				next_to_clean(q->retry);
				syslog(LOG_WARNING, "PEER mapping %hu %s expired, its rule was not deleted, "
				       "next try in %d s", b->eport, proto_itoa(b->proto), EXPIRY_RETRY);
				continue;
			}
			last = b->npeers == 1;
			memmap_drop_outgoing(b, &q->raddr, q->rport);
			if(last)
				break;	/* the binding went with its last peer */
		}
	}
#endif
}

/* Delete the rule at the place *i if it has no row, else go to the next
 * place. 1 while there are rules. */
static int
drop_if_no_row(int * i, int r, int known, struct fw_change * c, int * n)
{
	if(r < 0)
		return 0;
	if(r == 0 && !known) {
		if(fw_sync(c, 1) == 0) {
			(*n)++;
			return 1;	/* the rules after it moved down to *i */
		}
		syslog(LOG_WARNING, "a rule of an earlier run has no row, and could not be deleted");
	}
	(*i)++;
	return 1;
}

void
drop_rules_without_row(void)
{
	struct lease_entry * e = lease_table_new(1);
	struct fw_change c;
	int i, r, n = 0;
#ifdef FW_MAP6
	const struct lease_entry * row;
#endif
#if defined(PCP_PEER) && defined(USE_NETFILTER)
	struct outgoing_entry b;
	struct outgoing_peer q;
	struct fw_out_change oc;
#endif

	if(e == NULL)
		return;
	fw_change_init(&c, FW_DELETE, NULL, e);
	i = 0;
	do {
		r = fw_map_rule_at(i, e);
	} while(drop_if_no_row(&i, r,
	        r == 0 && lease_table_find_entry(e->proto, AF_INET, &e->iaddr,
	                                         e->iport, e->eport) != NULL,
	        &c, &n));
#ifdef FW_MAP6
	i = 0;
	do {
		r = fw_map6_rule_at(i, e);
		row = r == 0 ? lease_table_find_entry(e->proto, AF_INET6, &e->iaddr,
		                                      e->iport, e->iport) : NULL;
	} while(drop_if_no_row(&i, r,
	        row != NULL && (row->nfilters > 0 ?
	                        lease_filter_find(row, &e->filters[0].raddr,
	                                          e->filters[0].prefix,
	                                          e->filters[0].rport) != NULL :
	                        e->nfilters == 0),	/* the rule of any remote */
	        &c, &n));
#endif
	lease_table_free(e);
#if defined(PCP_PEER) && defined(USE_NETFILTER)
	/* a PEER rule goes by its external port, with the redirect rule on
	 * it: one which shares the port of a row stays. At startup a row of
	 * the lease file has the address ::, which memmap_find_map() takes
	 * for any. */
	memset(&b, 0, sizeof(b));
	memset(&q, 0, sizeof(q));
	b.peers = &q;
	for(i = 0; (r = fw_peer_rule_at(i, &b)) >= 0; ) {
		if(r == 0 &&
		   memmap_find_peer(b.proto, AF_INET, &b.iaddr, b.iport, &q.raddr, q.rport) == NULL &&
		   memmap_find_map(b.proto, AF_INET, &b.eaddr, b.eport) == NULL) {
			fw_out_change_init(&oc, FW_OUT_DELETE, &b, 0);
			if(fw_sync_out(&oc, 1) == 0) {
				n++;
				continue;
			}
			syslog(LOG_WARNING, "a PEER rule of an earlier run has no row, and could not be deleted");
		}
		i++;
	}
#endif
	if(n > 0)
		syslog(LOG_NOTICE, "%d rules of an earlier run had no row: deleted", n);
}

/* The rule_state list as an array sorted by protocol and port, so the
 * counters of each rule of fw_each_map_counters() find their entry. */
struct state_index {
	struct rule_state ** v;
	unsigned int n;
	int second;	/* the pass of remove_unused_rules() */
};

static int
state_cmp(const void * a, const void * b)
{
	const struct rule_state * x = *(struct rule_state * const *)a;
	const struct rule_state * y = *(struct rule_state * const *)b;

	if(x->proto != y->proto)
		return x->proto < y->proto ? -1 : 1;
	return x->eport < y->eport ? -1 : x->eport > y->eport;
}

/* 0, or -1 if there is no memory */
static int
state_index_build(struct state_index * ix, struct rule_state * list, int second)
{
	struct rule_state * s;
	unsigned int n = 0;

	ix->n = 0;
	ix->second = second;
	for(s = list; s != NULL; s = s->next)
		n++;
	ix->v = malloc((n > 0 ? n : 1) * sizeof(*ix->v));
	if(ix->v == NULL)
		return -1;
	for(s = list; s != NULL; s = s->next)
		ix->v[ix->n++] = s;
	qsort(ix->v, ix->n, sizeof(*ix->v), state_cmp);
	return 0;
}

/* first pass: the counters of the entry, which has a rule (to_remove 1);
 * second pass: to_remove 1 if they did not move */
static void
state_counters(unsigned short eport, int proto, u_int64_t packets, u_int64_t bytes,
               void * arg)
{
	const struct state_index * ix = arg;
	struct rule_state key, * kp = &key, ** r;

	key.eport = eport;
	key.proto = (unsigned char)proto;
	r = bsearch(&kp, ix->v, ix->n, sizeof(*ix->v), state_cmp);
	if(r == NULL)
		return;
	if(!ix->second) {
		(*r)->packets = packets;
		(*r)->bytes = bytes;
		(*r)->to_remove = 1;
	} else if(packets == (*r)->packets && bytes == (*r)->bytes) {
		(*r)->to_remove = 1;
	}
}

/* functions used to remove unused rules
 * As a side effect, delete expired rules (based on LeaseDuration) */
struct rule_state *
get_upnp_rules_state_list(int max_rules_number_target)
{
	const struct lease_entry * e;
	struct rule_state * tmp, ** pp;
	struct rule_state * list = 0;
	struct state_index ix;

	expire_mappings();
	if(lease_table_port_count() <= (unsigned int)max_rules_number_target)
		return NULL;
	/* Only UPnP mappings are removed when unused: those of PCP and
	 * NAT-PMP last the lifetime their client asked for. */
	for(e = lease_table_next_port(NULL); e != NULL; e = lease_table_next_port(e)) {
		if(e->kind != MAP_KIND_UPNP)
			continue;
		tmp = malloc(sizeof(struct rule_state));
		if(!tmp)
			break;
		tmp->eport = e->eport;
		tmp->proto = e->proto;
		tmp->to_remove = 0;
		tmp->next = list;
		list = tmp;
	}
	/* the counters of the rules: only the firewall has them, in one
	 * pass over its rules */
	if(state_index_build(&ix, list, 0) < 0 ||
	   fw_each_map_counters(state_counters, &ix) < 0) {
		ix.n = 0;	/* no counters: nothing is listed */
	}
	free(ix.v);
	/* keep the mappings with a rule, to_remove set back to 0 */
	for(pp = &list; *pp != NULL; ) {
		tmp = *pp;
		if(ix.n == 0 || !tmp->to_remove) {
			*pp = tmp->next;
			free(tmp);
		} else {
			tmp->to_remove = 0;
			pp = &tmp->next;
		}
	}
	return list;
}

void
remove_unused_rules(struct rule_state * list)
{
	struct rule_state * tmp;
	struct state_index ix;
	int n = 0;

	/* remove the rules no traffic has used since the first pass */
	if(state_index_build(&ix, list, 1) == 0) {
		if(fw_each_map_counters(state_counters, &ix) < 0)
			ix.n = 0;
		free(ix.v);
	}
	while(list)
	{
		if(list->to_remove)
		{
			syslog(LOG_DEBUG, "removing unused mapping %hu %s : still "
			       "%" PRIu64 "packets %" PRIu64 "bytes",
			       list->eport, proto_itoa(list->proto),
			       list->packets, list->bytes);
			upnp_delete_port(list->eport, list->proto);
			n++;
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
	const struct lease_entry * e;
	char desc[64];
	char iaddr[INET_ADDRSTRLEN];
	char rhost[INET6_ADDRSTRLEN];
	const char * r;
	u_int64_t packets;
	u_int64_t bytes;
	int i = 0;
	char buffer[256];
	int n;

	/* the port mappings of the table, with the counters of their rules,
	 * which only the firewall has */
	write(s, "Ruleset :\n", 10);
	for(e = lease_table_next_port(NULL); e != NULL; e = lease_table_next_port(e)) {
		if(fw_map_rule(e->eport, e->proto, &packets, &bytes) != 0)
			packets = bytes = 0;
		if(map_ntop(AF_INET, &e->iaddr, iaddr, sizeof(iaddr)) == NULL)
			iaddr[0] = '\0';
		r = map_rhost(e, rhost, sizeof(rhost));
		n = snprintf(buffer, sizeof(buffer),
		             "%2d %s %s:%hu->%s:%hu "
		             "'%s' %u %" PRIu64 " %" PRIu64 "\n",
		             i, proto_itoa(e->proto), r ? r : "",
		             e->eport, iaddr, e->iport,
		             map_rule_desc(e, desc, sizeof(desc)), e->timestamp,
		             packets, bytes);
		if(n > 0 && n < (int)sizeof(buffer))
			write(s, buffer, n);
		i++;
	}
}
#endif
