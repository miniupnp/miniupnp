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
#ifdef OS_VERSION_FILE
#include <stdio.h>
#include <ctype.h>
#endif

char * get_os_version(void)
{
	struct utsname utsname;
#ifdef OS_VERSION_FILE
	FILE * f;

	f = fopen(OS_VERSION_FILE, "r");
	if (f != NULL) {
		char buffer[256];
		char * p;
		p = fgets(buffer, sizeof(buffer), f);
		fclose(f);
		if (p != NULL) {
			/* trim the string */
			char * p = buffer + strlen(buffer);
			while (p > buffer && isspace(p[-1]))
				*(--p) = '\0';
			p = buffer;
			while (isspace(*p))
			    p++;
			return strdup(p);
		}
	}
#endif

	if (uname(&utsname) < 0) {
		syslog(LOG_ERR, "uname(): %m");
		return strdup("unknown");
	} else {
		return strdup(utsname.release);
	}
}
#endif
