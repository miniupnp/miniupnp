/* The map6 rules of a firewall backend, found by their key.
 *
 * The key of a map6 is its internal address and port, its protocol, and its
 * remote address and port, which may be none: rem_host NULL, "", "*" or "::".
 * The firewall does not know the uid of a map6, nor its expiry: those are
 * the map's, which expires the map6s from its table. The label of a rule
 * holds its description, for people, and marks it as a map6 of the daemon.
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
 * startup. rem_host is "" for none. 0, or -1 past the end */
int get_map6_rule_at(int index, char * rem_host, int rem_hostlen,
                        unsigned short * rem_port,
                        char * int_client, int int_clientlen,
                        unsigned short * int_port, int * proto,
                        char * desc, int desclen);

/* The label of a map6 rule: "pinhole: <description>". The word is the one
 * older daemons wrote, so their rules are known as the daemon's too. */
static inline void
map6_label(char * label, size_t len, const char * desc)
{
	snprintf(label, len, "pinhole: %s", desc ? desc : "");
}

/* The description in the label of a map6 rule, or NULL if the label is not
 * that of a map6 of the daemon. The labels of older daemons, with a uid and
 * an expiry before the description, are map6s too. */
static inline const char *
map6_label_desc(const char * label)
{
	const char * p;
	if(strncmp(label, "pinhole", 7) != 0)
		return NULL;
	p = strstr(label, ": ");
	return p != NULL ? p + 2 : label + strlen(label);
}

/* 1 if rem_host stands for no remote */
static inline int
map6_any_remote(const char * rem_host)
{
	return rem_host == NULL || rem_host[0] == '\0' || rem_host[0] == '*' ||
	       strcmp(rem_host, "::") == 0;
}

#endif
