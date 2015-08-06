/* $Id: config.h,v 1.9 2015/08/06 13:16:58 nanard Exp $ */
/*  MiniUPnP project
 * http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * (c) 2006-2015 Thomas Bernard
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */
#ifndef CONFIG_H_INCLUDED
#define CONFIG_H_INCLUDED

#define MINISSDPD_VERSION "1.3"

/* use BSD daemon() ? */
#define USE_DAEMON

/* set the syslog facility to use. See man syslog(3) and syslog.conf(5). */
#define LOG_MINISSDPD	LOG_DAEMON

/* enable IPv6 */
#define ENABLE_IPV6

/* Maximum number of network interface we can listen on */
#define MAX_IF_ADDR 8

/* The size of unix socket response buffer */
#define RESPONSE_BUFFER_SIZE (1024 * 4)

/* Uncomment the following line in order to make minissdpd
 * listen on 1.2.3.4:1900 instead of *:1900
 * Note : it prevents broadcast packets to be received,
 *        at least with linux */
/*#define SSDP_LISTEN_ON_SPECIFIC_ADDR*/

#endif
