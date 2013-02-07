/* $Id: ifacewatch.h,v 1.1 2011/07/29 15:21:13 nanard Exp $ */
/* MiniUPnP project
 * http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * (c) 2011 Thomas Bernard
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

#ifndef IFACEWATCH_H_INCLUDED
#define IFACEWATCH_H_INCLUDED

int
OpenAndConfInterfaceWatchSocket(void);

int
ProcessInterfaceWatch(int s, int s_ssdp, int s_ssdp6,
                      int n_if_addr, const char * * if_addr);

#endif
