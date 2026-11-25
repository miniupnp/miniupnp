/* $Id: iptpinhole.h,v 1.5 2012/05/08 20:41:45 nanard Exp $ */
/* MiniUPnP project
 * http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * (c) 2012-2016 Thomas Bernard
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */
#ifndef IPTPINHOLE_H_INCLUDED
#define IPTPINHOLE_H_INCLUDED

#ifdef ENABLE_UPNPPINHOLE
#include <sys/types.h>
#include "../fwmap6.h"

/* the map6 rules are those of fwmap6.h, found in the chain by their key */
void init_iptpinhole(void);
void shutdown_iptpinhole(void);

#endif /* ENABLE_UPNPPINHOLE */

#endif
