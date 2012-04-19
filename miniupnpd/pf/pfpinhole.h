/* $Id: pfpinhole.h,v 1.2 2012/04/19 22:02:12 nanard Exp $ */
/* MiniUPnP project
 * http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * (c) 2012 Thomas Bernard
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

#ifndef __PFPINHOLE_H__
#define __PFPINHOLE_H__

int add_pinhole (const char * ifname,
                 const char * rem_host, unsigned short rem_port,
                 const char * int_client, unsigned short int_port,
                 int proto);

int delete_pinhole (unsigned short uid);

#endif

