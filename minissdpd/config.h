/* $Id: config.h,v 1.4 2011/05/23 12:22:29 nanard Exp $ */
/*  MiniUPnP project
 * http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * (c) 2006-2011 Thomas Bernard
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */
#ifndef CONFIG_H_INCLUDED
#define CONFIG_H_INCLUDED

/* use BSD daemon() ? */
#define USE_DAEMON

/* set the syslog facility to use. See man syslog(3) and syslog.conf(5). */
#define LOG_MINISSDPD	LOG_DAEMON

/* enable IPv6 */
#define ENABLE_IPV6

/* Maximum number of network interface we can listen on */
#define MAX_IF_ADDR 8

#endif
