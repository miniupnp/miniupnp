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
 * and PCP (IPv6). Each req has exactly one filter: filters[0] */

#if 0
/* retrieve outbound pinhole timeout */
int
upnp_check_outbound_pinhole(int proto, int * timeout);
#endif

/* find the inbound pinhole of req: its first filter, the remote, and its
 * internal side. Sets the uid of the filter.
 * return the (positive) uid or a negative value if not found */
int
upnp_find_inboundpinhole(struct lease_entry * req,
                         char * desc, int desc_len, unsigned int * leasetime);


/* add an inbound pinhole, or renew the one of the same remote and
 * internal endpoint. req: the IPv6 iaddr, iport, proto, timestamp and one
 * filter, the remote; its uid is set on success. The rule gets
 * map_rule_desc().
 * return value :
 *  1 = success
 * -1 = Pinhole space exhausted
 * .. = error */
int
upnp_add_inboundpinhole(struct lease_entry * req);

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

/* renew the pinhole of the uid of the first filter of req to
 * req->timestamp */
int
upnp_update_inboundpinhole(const struct lease_entry * req);

/* remove the inbound pinhole a client asks to delete: the uid of the first
 * filter of req */
int
upnp_delete_inboundpinhole(const struct lease_entry * req);

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
