/* vim: tabstop=4 shiftwidth=4 noexpandtab
 * MiniUPnP project
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * (c) 2006-2026 Thomas Bernard
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

#include "config.h"

#ifdef DYNAMIC_OS_VERSION
#include <sys/utsname.h>
#include <syslog.h>
#include <string.h>

char * get_os_version(void)
{
	char * ret = NULL;
	struct utsname utsname;
	if (uname(&utsname) < 0) {
		syslog(LOG_ERR, "uname(): %m");
		ret = strdup("unknown");
	} else {
		ret = strdup(utsname.release);
	}
	return ret;
}
#endif
