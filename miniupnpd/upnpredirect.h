/* $Id: upnpredirect.h,v 1.36 2018/01/16 00:50:49 nanard Exp $ */
/* vim: tabstop=4 shiftwidth=4 noexpandtab
 * MiniUPnP project
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * (c) 2006-2026 Thomas Bernard
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

#ifndef UPNPREDIRECT_H_INCLUDED
#define UPNPREDIRECT_H_INCLUDED

/* for u_int64_t */
#include <sys/types.h>

#include "config.h"

/*! \file upnpredirect.h
 * \brief backend independent functions for redirection
 */

#ifdef ENABLE_LEASEFILE
int reload_from_lease_file(void);
#ifdef LEASEFILE_USE_REMAINING_TIME
void lease_file_rewrite(void);
#endif
#endif

/*! \brief add a port mapping.
 * calls OS/fw dependent implementation of the port mapping (redirection).
 * \param[in] rhost Remote host or NULL
 * \param[in] eport external port
 * \param[in] iaddr internal IPv4 address
 * \param[in] iport internal port
 * \param[in] protocol "TCP" or "UDP" (or "UDPLITE" if supported)
 * \param[in] desc port mapping description
 * \param[in] leaseduration lease duration in seconds (0 for infinite)
 * \return 0 on success, -1 failed to redirect,
 *         -2 already redirected, -3 permission check failed
 */
int
upnp_redirect(const char * rhost, unsigned short eport,
              const char * iaddr, unsigned short iport,
              const char * protocol, const char * desc,
              unsigned int leaseduration);

/*! \brief same as upnp_redirect() without any check
 * \param[in] rhost Remote host or NULL
 * \param[in] eport external port
 * \param[in] iaddr internal IPv4 address
 * \param[in] iport internal port
 * \param[in] proto IPPROTO_TCP or IPPROTO_UDP (or IPPROTO_UDPLITE if supported)
 * \param[in] desc port mapping description
 * \param[in] timestamp unix epoch of the end of the port mapping, or 0 for infinite duration
 * \return 0 on success, -1 failed to redirect,
 *         -2 already redirected, -3 permission check failed
 */
int
upnp_redirect_internal(const char * rhost, unsigned short eport,
                       const char * iaddr, unsigned short iport,
                       int proto, const char * desc,
                       unsigned int timestamp);

/*! \brief get port mapping from (external port, protocol)
 * \param[in] eport external port
 * \param[in] protocol "TCP" or "UDP" (or "UDPLITE" if supported)
 * \param[out] iport internal port
 * \param[out] iaddr internal IPv4 address
 * \param[in] iaddrlen iaddr buffer length
 * \param[out] desc port mapping description
 * \param[in] desclen desc buffer length
 * \param[out] rhost remote host
 * \param[in] rhostlen rhost buffer length
 * \param[out] leaseduration lease duration in seconds (0 for infinite)
 * \return 0 on success, -1 failed to get the port mapping entry or no entry exists */
int
upnp_get_redirection_infos(unsigned short eport, const char * protocol,
                           unsigned short * iport, char * iaddr, int iaddrlen,
                           char * desc, int desclen,
                           char * rhost, int rhostlen,
                           unsigned int * leaseduration);

/*! \brief get port mapping from index
 * \param[in] index 0-based index of the port mapping to get
 * \param[out] eport external port
 * \param[out] protocol "TCP" or "UDP" (or "UDPLITE" if supported)
 * \param[out] iport internal port
 * \param[out] iaddr internal IPv4 address
 * \param[in] iaddrlen iaddr buffer length
 * \param[out] desc port mapping description
 * \param[in] desclen desc buffer length
 * \param[out] rhost remote host
 * \param[in] rhostlen rhost buffer length
 * \param[out] leaseduration lease duration in seconds (0 for infinite)
 * \return 0 on success, -1 failed to get the port mapping entry or no entry exists */
int
upnp_get_redirection_infos_by_index(int index,
                                    unsigned short * eport, char * protocol,
                                    unsigned short * iport,
                                    char * iaddr, int iaddrlen,
                                    char * desc, int desclen,
                                    char * rhost, int rhostlen,
                                    unsigned int * leaseduration);

/*! \brief get a port mapping from its internal tuple (address, port, protocol)
 *
 * That is the destination of the port mapping, when the external port
 * is the source.
 * \param[in] iport internal port
 * \param[in] iaddr internal IPv4 address
 * \param[in] proto IPPROTO_TCP or IPPROTO_UDP (or IPPROTO_UDPLITE if supported)
 * \param[out] eport external port
 * \param[out] desc port mapping description
 * \param[in] desclen desc buffer length
 * \param[out] rhost remote host
 * \param[in] rhostlen rhost buffer length
 * \param[out] leaseduration lease duration in seconds (0 for infinite)
 * \return 0 on success, -1 failed to get the port mapping entry or no entry exists */
int
upnp_get_redirection_infos_by_ituple(unsigned short iport,
                                     const char * iaddr, int proto,
                                     unsigned short * eport,
                                     char * desc, int desclen,
                                     char * rhost, int rhostlen,
                                     unsigned int * leaseduration);

/*! \brief delete a port mapping based on (external port, protocol)
 * \param[in] eport external port
 * \param[in] protocol "TCP" or "UDP" (or "UDPLITE" if supported)
 * \return 0 on success, -1 on failure*/
int
upnp_delete_redirection(unsigned short eport, const char * protocol);

/*! \brief delete a port mapping based on (external port, protocol).
 *
 * same as _upnp_delete_redir()
 * \param[in] eport external port
 * \param[in] proto IPPROTO_TCP or IPPROTO_UDP (or IPPROTO_UDPLITE if supported)
 * \return 0 on success, -1 on failure*/
int
_upnp_delete_redir(unsigned short eport, int proto);

/* Periodic cleanup functions
 */
struct rule_state
{
	u_int64_t packets;
	u_int64_t bytes;
	struct rule_state * next;
	unsigned short eport;
	unsigned char proto;
	unsigned char to_remove;
};

/* return a linked list of all rules
 * or an empty list if there are not enough
 * As a "side effect", delete rules which are expired */
struct rule_state *
get_upnp_rules_state_list(int max_rules_number_target);

/*! \brief return the number of port mapping entries
 * \return the number of port mapping entries */
int
upnp_get_portmapping_number_of_entries(void);

/* remove_unused_rules() :
 * also free the list */
void
remove_unused_rules(struct rule_state * list);

/*! \brief returns a list of all "external" ports for which a port
 * mapping exists
 * \param[in] startport lowest port in the interval
 * \param[in] endport highest port in theinterval
 * \param[in] protocol "TCP" or "UDP" (or "UDPLITE" if supported)
 * \param[out] number number of ports in the returned array
 * \return a malloc'ed array of ports or NULL for error
 */
unsigned short *
upnp_get_portmappings_in_range(unsigned short startport,
                               unsigned short endport,
                               const char * protocol,
                               unsigned int * number);

/* stuff for responding to miniupnpdctl */
#ifdef USE_MINIUPNPDCTL
void
write_ruleset_details(int s);
#endif

#endif
