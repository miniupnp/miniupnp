/* vim: tabstop=4 shiftwidth=4 noexpandtab
 * MiniUPnP project
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * (c) 2006-2026 Thomas Bernard
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */
#ifndef GETOSVERSION_H_INCLUDED
#define GETOSVERSION_H_INCLUDED
#include "config.h"

#ifdef DYNAMIC_OS_VERSION
char * get_os_version(void);
#endif /* DYNAMIC_OS_VERSION */

#endif /* GETOSVERSION_H_INCLUDED */
