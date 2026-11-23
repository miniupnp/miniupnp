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
int lease_file6_expire(void);
#endif

/* functions to be used by WANIPv6_FirewallControl implementation
 * and PCP (IPv6). A UPnP req has one filter, filters[0]: the remote, and the
 * uid of the pinhole. A PCP req has none: its one rule lets any remote in. */

#if 0
/* retrieve outbound pinhole timeout */
int
upnp_check_outbound_pinhole(int proto, int * timeout);
#endif

/* find the inbound pinhole of req: the remote of its filter (any remote if
 * it has none) and its internal side. Sets the uid of the filter.
 * return the (positive) uid or a negative value if not found */
int
upnp_find_inboundpinhole(struct lease_entry * req,
                         char * desc, int desc_len, unsigned int * leasetime);


/* add an inbound pinhole, or renew the one of the same remote and
 * internal endpoint. req: the IPv6 iaddr, iport, proto, timestamp and its
 * filter, the remote, or none for any remote. The rule gets map_rule_desc(). On success *uid_out
 * (if not NULL) is the uid of the pinhole, and the lease table takes a row
 * of lease_table_new() (memmap_add(), or memmap_update() for the pinhole
 * there was): the caller frees req only on failure.
 * return value :
 *  1 = success
 * -1 = Pinhole space exhausted
 * .. = error */
int
upnp_add_inboundpinhole(struct lease_entry * req, unsigned short * uid_out);

/* get from uid
 * return values :
 *  -1 not found
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

/*
 * return values:
 * -1 = not found
 * 0 .. 65535 = uid of the rule for the index
 */
int
upnp_get_pinhole_uid_by_index(int index);

/* renew the pinhole uid of req to req->timestamp */
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

/* return the number of expired pinhole removed
 * write timestamp to next pinhole to exprire to next_timestamp
 * next_timestamp is left untouched if there is no pinhole lest */
int
upnp_clean_expired_pinholes(unsigned int * next_timestamp);

#endif /* ENABLE_UPNPPINHOLE */

#endif /* !UPNPPINHOLE_H_INCLUDED */
