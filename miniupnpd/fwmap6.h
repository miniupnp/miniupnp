/* The map6 rules of a firewall backend, found by their key.
 *
 * The key of a map6 is its internal address and port, its protocol, and its
 * remote address and port, which may be none: rem_host NULL, "", "*" or "::".
 * The firewall does not know the uid of a map6, its expiry nor its
 * description: those are the map's, which expires the map6s from its table.
 * A rule holds no label: a map6 of the daemon is an IPv6 forward rule of
 * its chain or anchor.
 *
 * nftables and pf implement this. iptables keeps its own list of map6s,
 * and implements it on top of that list. */
#ifndef FWMAP6_H_INCLUDED
#define FWMAP6_H_INCLUDED

#include <stdio.h>
#include <string.h>
#include <sys/types.h>

/* Add the rule of a map6. 0, or < 0 */
int add_map6_rule(const char * ifname,
                     const char * rem_host, unsigned short rem_port,
                     const char * int_client, unsigned short int_port,
                     int proto, const char * desc, unsigned int timestamp);

/* Give the rule of a map6 a new expiry and description. 0, -2 if there is
 * no such rule, or < 0 */
int update_map6_rule(const char * ifname,
                        const char * rem_host, unsigned short rem_port,
                        const char * int_client, unsigned short int_port,
                        int proto, const char * desc, unsigned int timestamp);

/* Delete the rule of a map6. 0, -2 if there is no such rule, or < 0 */
int delete_map6_rule(const char * rem_host, unsigned short rem_port,
                        const char * int_client, unsigned short int_port,
                        int proto);

/* The packet counter of the rule of a map6. 0, -2 if there is no such
 * rule, or < 0 */
int get_map6_packets(const char * rem_host, unsigned short rem_port,
                        const char * int_client, unsigned short int_port,
                        int proto, u_int64_t * packets);

/* The map6 rule at this place, to find the rules of an earlier run at
 * startup. rem_host is "" for none. A map6 rule is an IPv6 forward rule of
 * the daemon's chain or anchor: it holds no label, so desc is always "".
 * 0, or -1 past the end or when the rules cannot be read */
int get_map6_rule_at(int index, char * rem_host, int rem_hostlen,
                        unsigned short * rem_port,
                        char * int_client, int int_clientlen,
                        unsigned short * int_port, int * proto,
                        char * desc, int desclen);

/* 1 if rem_host stands for no remote */
static inline int
map6_any_remote(const char * rem_host)
{
	return rem_host == NULL || rem_host[0] == '\0' || rem_host[0] == '*' ||
	       strcmp(rem_host, "::") == 0;
}

#endif
