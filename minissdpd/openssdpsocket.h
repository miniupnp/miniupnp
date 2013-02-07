/* $Id: openssdpsocket.h,v 1.4 2011/07/29 15:21:13 nanard Exp $ */
/* MiniUPnP project
 * http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * (c) 2006-2011 Thomas Bernard
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */
#ifndef OPENSSDPSOCKET_H_INCLUDED
#define OPENSSDPSOCKET_H_INCLUDED

/**
 * Open a socket and configure it for receiving SSDP packets
 *
 * @param n_listen_addr	size of listen_addr array
 * @param listen_addr	array of address (or interface names) to listen
 * @param ipv6	open INET6 or INET socket
 * @return socket
 */
int
OpenAndConfSSDPReceiveSocket(int n_if_addr,
                             const char * * if_addr,
                             int ipv6);

/**
 * Add or Drop the multicast membership for SSDP on the interface
 * @param s	the socket
 * @param ifaddr	the IPv4 address or interface name
 * @param ipv6	IPv6 or IPv4
 * @param drop	0 to add, 1 to drop
 * return -1 on error, 0 on success */
int
AddDropMulticastMembership(int s, const char * ifaddr, int ipv6, int drop);

#endif

