/* $Id: commonrdr.h,v 1.17 2025/04/03 21:11:34 nanard Exp $ */
/* MiniUPnP project
 * (c) 2006-2025 Thomas Bernard
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */
#ifndef COMMONRDR_H_INCLUDED
#define COMMONRDR_H_INCLUDED

/*! \file commonrdr.h
 * \brief common API for all backends
 */

#include "config.h"

/* init and shutdown functions */

/*! \brief init the backend
 * \return 0=OK, -1=error
 */
int
init_redirect(void);

/*! \brief shutdown the backend */
void
shutdown_redirect(void);


#include <netinet/in.h>

/*! \brief the key of a PEER rule (SNAT) of netfilter: iaddr:iport out to
 * raddr:rport on eport. Addresses in network order, ports in host order. */
struct outgoing_rule_key {
	in_addr_t iaddr;
	in_addr_t raddr;
	unsigned short iport;
	unsigned short rport;
	unsigned short eport;
	unsigned char proto;
	signed char result;	/*!< set by outgoing_rule_delete(): 0 deleted,
				 * -2 the firewall has no such rule */
};

/*! \brief the most keys of one outgoing_rule_delete() */
#define OUTGOING_RULE_DELETE_MAX 64

/*! \brief get port mapping by external port and protocol
 * \param[in] ifname WAN interface name
 * \param[in] eport external port
 * \param[in] proto IPPROTO_TCP/IPPROTO_UDP/etc.
 * \return 0 on success, -1 on error or rule not found */
int
get_redirect_rule(const char * ifname, unsigned short eport, int proto,
                  char * iaddr, int iaddrlen, unsigned short * iport,
                  char * desc, int desclen,
                  char * rhost, int rhostlen,
                  unsigned int * timestamp,
                  u_int64_t * packets, u_int64_t * bytes);

/*! \brief get port mapping by index
 * \param[in] index
 * \return 0 on success, -1 on error or rule not found */
int
get_redirect_rule_by_index(int index,
                           char * ifname, unsigned short * eport,
                           char * iaddr, int iaddrlen, unsigned short * iport,
                           int * proto, char * desc, int desclen,
                           char * rhost, int rhostlen,
                           unsigned int * timestamp,
                           u_int64_t * packets, u_int64_t * bytes);

/*! \brief update the port mapping internal port, description and timestamp
 * \param[in] ifname WAN interface name
 * \param[in] eport external port
 * \param[in] proto IPPROTO_TCP/IPPROTO_UDP/etc.
 * \param[in] iport internal port to set
 * \param[in] desc new description to set
 * \param[in] timestamp new end of port mapping timestamp to set
 * \return 0 on success, -1 on failure */
int
update_portmapping(const char * ifname, unsigned short eport, int proto,
                   unsigned short iport, const char * desc,
                   unsigned int timestamp);

/*! \brief update the port mapping description and timestamp
 * \param[in] ifname WAN interface name
 * \param[in] eport external port
 * \param[in] proto IPPROTO_TCP/IPPROTO_UDP/etc.
 * \param[in] desc new description to set
 * \param[in] timestamp new end of port mapping timestamp to set
 * \return 0 on success, -1 on failure */
int
update_portmapping_desc_timestamp(const char * ifname,
                   unsigned short eport, int proto,
                   const char * desc, unsigned int timestamp);

#if defined(USE_NETFILTER)
/*
 * only provided by nftables implementation at the moment.
 * Should be implemented for iptables too, for consistency
 */

typedef enum {
	RDR_TABLE_NAME,
	RDR_NAT_TABLE_NAME,
	RDR_NAT_PREROUTING_CHAIN_NAME,
	RDR_NAT_POSTROUTING_CHAIN_NAME,
	RDR_FORWARD_CHAIN_NAME,
	RDR_FAMILY_SPLIT,
} rdr_name_type;

/*
 * used by the config file parsing in the core
 * to set
 */

int set_rdr_name( rdr_name_type param, const char * string );

#endif

#endif
