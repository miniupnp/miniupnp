/* $Id: iptpinhole.h,v 1.2 2012/04/26 14:01:17 nanard Exp $ */
/* MiniUPnP project
 * http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * (c) 2012 Thomas Bernard
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */
#ifndef __IPTPINHOLE_H__
#define __IPTPINHOLE_H__

#ifdef ENABLE_6FC_SERVICE
int add_pinhole(const char * ifname,
                const char * rem_host, unsigned short rem_port,
                const char * int_client, unsigned short int_port,
                int proto);
#endif

#endif
