/* MiniUPnP project
 * The lifetime of the PCP PEER mappings, for the firewall backends : a PEER
 * rule is in the firewall, its expiry is here.
 * This software is subject to the conditions detailed in the LICENCE file.
 */
#ifndef PEER_LEASE_H_INCLUDED
#define PEER_LEASE_H_INCLUDED

#include <netinet/in.h>

/* a PEER mapping is identified by its two endpoints and the protocol
 * (addresses in network byte order, ports in host byte order).
 * timestamp : expiry in the time of upnp_time(), 0 for none. */

/* is there a lease for this PEER mapping ? */
int peer_lease_exists(in_addr_t iaddr, unsigned short iport,
                      in_addr_t raddr, unsigned short rport, int proto);
/* its expiry (0 if there is none or no lease) */
unsigned int peer_lease_get(in_addr_t iaddr, unsigned short iport,
                            in_addr_t raddr, unsigned short rport, int proto);
/* create or update the lease. returns -1 if out of memory */
int peer_lease_set(in_addr_t iaddr, unsigned short iport,
                   in_addr_t raddr, unsigned short rport, int proto,
                   unsigned int timestamp);
void peer_lease_remove(in_addr_t iaddr, unsigned short iport,
                       in_addr_t raddr, unsigned short rport, int proto);
void peer_lease_free_all(void);

/* remove the PEER mappings which expired at 'now' with delete() (the
 * delete_peer_rule() of the backend, it also removes the lease). A mapping
 * which could not be removed is tried again later.
 * returns the time of the next expiry (0 if none) */
typedef int (*peer_lease_delete_cb)(const char * iaddr, unsigned short iport,
                                    const char * raddr, unsigned short rport,
                                    int proto);
unsigned int peer_lease_expire(unsigned int now, peer_lease_delete_cb delete);

#endif
