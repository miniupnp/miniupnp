/* vim: tabstop=4 shiftwidth=4 noexpandtab
 * MiniUPnP project
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * (c) 2021 Pali Rohár
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

#ifndef UPNPFORWARDCHECK_H_INCLUDED
#define UPNPFORWARDCHECK_H_INCLUDED

int perform_forwarding_check(const char *if_name, const char *if_addr_str, struct in_addr *if_addr, struct in_addr *ext_addr);

#endif
