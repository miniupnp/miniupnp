/* $Id: upnppinhole.h,v 1.7 2021/08/21 08:12:49 nanard Exp $ */
/* vim: tabstop=4 shiftwidth=4 noexpandtab
 * MiniUPnP project
 * http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * (c) 2006-2021 Thomas Bernard
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

#ifndef UPNPPINHOLE_H_INCLUDED
#define UPNPPINHOLE_H_INCLUDED

#include "config.h"
#include "mapreq.h"

#ifdef ENABLE_UPNPPINHOLE

#ifdef ENABLE_LEASEFILE
int reload_from_lease_file6(void);
#endif

/* functions to be used by WANIPv6_FirewallControl implementation
 * and PCP (IPv6). A UPnP req has one filter, filters[0]: the remote, and the
 * uid of the pinhole. A PCP req has none: its one rule lets any remote in. */

#if 0
/* retrieve outbound pinhole timeout */
int
upnp_check_outbound_pinhole(int proto, int * timeout);
#endif

/* find the IPv6 map of req in the lease table, by the internal side and
 * the remote of its filter (any remote if it has none): its row (owner,
 * expiry), or NULL. For a UPnP request, sets the uid of the filter, its
 * UniqueID; PCP uses none. */
const struct lease_entry *
upnp_find_inboundpinhole(struct lease_entry * req);


/* add an inbound pinhole, or renew the one of the same remote and
 * internal endpoint. req: the IPv6 iaddr, iport, proto, timestamp and its
 * filter, the remote, or none for any remote. The rule gets map_rule_desc(). On success *uid_out
 * (if not NULL) is the uid of the pinhole, and the lease table takes a row
 * of lease_table_new() (memmap_add(), or memmap_update() for the pinhole
 * there was): the caller frees req only on failure. req->eport is the
 * external port asked, 0 : any; with MAP_PREFER_FAILURE another than iport
 * fails, as an IPv6 map has no translation, else it becomes iport.
 * return value :
 *  1 = success
 * -1 = Pinhole space exhausted
 * -3 = the external port asked cannot be given
 * .. = error */
int
upnp_add_inboundpinhole(struct lease_entry * req, unsigned short * uid_out);

/* get from uid, in the lease table: a UPnP pinhole. packets is the
 * counter of the rule, read from the firewall when it is not NULL.
 * return values :
 *   0 OK
 *  -1 the firewall did not give the counter
 *  -2 not found
 * */
int
upnp_get_pinhole_info(unsigned short uid,
                      char * raddr, int raddrlen,
                      unsigned short * rport,
                      char * iaddr, int iaddrlen,
                      unsigned short * iport,
                      int * proto, char * desc, int desclen,
                      unsigned int * leasetime,
                      unsigned int * packets);

/* renew the map6 of req to req->timestamp: the map of uid, or with uid 0
 * the map of its key. 0, -1 if there is none, -2 if its rules were lost
 * and could not be added back */
int
upnp_update_inboundpinhole(const struct lease_entry * req, unsigned short uid);

/* remove the inbound pinhole uid of req, which a client asks to delete */
int
upnp_delete_inboundpinhole(const struct lease_entry * req, unsigned short uid);

/* ... */
#if 0
int
upnp_check_pinhole_working(const char * uid, char * eaddr, char * iaddr, unsigned short * eport, unsigned short * iport, char * protocol, int * rulenum_used);
#endif

/* delete the rules of the IPv6 map e, a row of the table, its lease file
 * lines and its row. 0, or -1 if a rule stays: e stays too */
int
upnp_delete_map6(struct lease_entry * e);

#endif /* ENABLE_UPNPPINHOLE */

#endif /* !UPNPPINHOLE_H_INCLUDED */
