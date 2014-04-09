/* $Id: minissdp.h,v 1.12 2014/04/09 07:20:59 nanard Exp $ */
/* MiniUPnP project
 * http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * (c) 2006-2007 Thomas Bernard
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */
#ifndef MINISSDP_H_INCLUDED
#define MINISSDP_H_INCLUDED

#include "miniupnpdtypes.h"

int
OpenAndConfSSDPReceiveSocket(int ipv6);

int
OpenAndConfSSDPNotifySockets(int * sockets);
/*OpenAndConfSSDPNotifySockets(int * sockets,
                             struct lan_addr_s * lan_addr, int n_lan_addr);*/

/*void
SendSSDPNotifies(int s, const char * host, unsigned short port,
                 unsigned int lifetime);*/
void
SendSSDPNotifies2(int * sockets,
                  unsigned short port,
#ifdef ENABLE_HTTPS
                  unsigned short https_port,
#endif
                  unsigned int lifetime);
/*SendSSDPNotifies2(int * sockets, struct lan_addr_s * lan_addr, int n_lan_addr,
                  unsigned short port,
                  unsigned int lifetime);*/

void
#ifdef ENABLE_HTTPS
ProcessSSDPRequest(int s, unsigned short port, unsigned short https_port);
#else
ProcessSSDPRequest(int s, unsigned short port);
#endif
/*ProcessSSDPRequest(int s, struct lan_addr_s * lan_addr, int n_lan_addr,
                   unsigned short port);*/

void
ProcessSSDPData(int s, const char *bufr, int n,
                const struct sockaddr * sendername,
#ifdef ENABLE_HTTPS
                unsigned short port, unsigned short https_port);
#else
                unsigned short port);
#endif

int
SendSSDPGoodbye(int * sockets, int n);

int
SubmitServicesToMiniSSDPD(const char * host, unsigned short port);

#endif

