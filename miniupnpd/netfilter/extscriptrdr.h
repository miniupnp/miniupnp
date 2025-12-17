/* $Id$ */
/* vim: tabstop=4 shiftwidth=4 noexpandtab
 * MiniUPnP project
 * External script wrapper for port forwarding operations
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

#ifndef EXTSCRIPTRDR_H_INCLUDED
#define EXTSCRIPTRDR_H_INCLUDED

/* ext_add_redirect_rule2()
 * Add port forwarding rule using external script */
int
ext_add_redirect_rule2(const char * ifname,
                       const char * rhost, unsigned short eport,
                       const char * iaddr, unsigned short iport, int proto,
                       const char * desc, unsigned int timestamp);

/* ext_add_filter_rule2()
 * Add filter rule using external script */
int
ext_add_filter_rule2(const char * ifname,
                     const char * rhost, const char * iaddr,
                     unsigned short eport, unsigned short iport,
                     int proto, const char * desc);

/* ext_delete_redirect_rule()
 * Delete port forwarding rule using external script */
int
ext_delete_redirect_rule(const char * ifname, unsigned short eport, int proto);

/* ext_delete_filter_rule()
 * Delete filter rule using external script */
int
ext_delete_filter_rule(const char * ifname, unsigned short eport, int proto);

/* ext_delete_redirect_and_filter_rules()
 * Delete both redirect and filter rules */
int
ext_delete_redirect_and_filter_rules(unsigned short eport, int proto);

#endif /* EXTSCRIPTRDR_H_INCLUDED */
